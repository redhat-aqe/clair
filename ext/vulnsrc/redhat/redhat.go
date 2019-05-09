// Copyright 2019 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package redhat implements a vulnerability source updater using the
// Red Hat Vmaas API.
// https://github.com/RedHatInsights/vmaas
package redhat

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/pkg/brew"
	"github.com/coreos/clair/pkg/commonerr"
	"github.com/coreos/clair/pkg/httputil"
	"github.com/patrickmn/go-cache"
)

const (
	rhsaFirstTime     = "2000-01-01T01:01:01+02:00"
	cveURL            = "https://access.redhat.com/security/cve/"
	updaterFlag       = "redHatUpdater"
	additionalAdvFlag = "vmasAdditionalAdv"
	affectedType      = database.BinaryPackage
	brewHub           = "http://brewhub.engineering.redhat.com/brewhub"
)

type Advisory struct {
	Name          string    `json:"name"`
	Synopsis      string    `json:"synopsis"`
	Summary       string    `json:"summary"`
	Type          string    `json:"type"`
	Severity      string    `json:"severity"`
	Description   string    `json:"description"`
	Solution      string    `json:"solution"`
	Issued        time.Time `json:"issued"`
	Updated       time.Time `json:"updated"`
	CveList       []string  `json:"cve_list"`
	PackageList   []string  `json:"package_list"`
	BugzillaList  []string  `json:"bugzilla_list"`
	ReferenceList []string  `json:"reference_list"`
	URL           string    `json:"url"`
}

type RHSAdata struct {
	ErrataList    map[string]Advisory `json:"errata_list"`
	Page          int                 `json:"page"`
	PageSize      int                 `json:"page_size"`
	Pages         int                 `json:"pages"`
	ModifiedSince string              `json:"modified_since"`
}

type VmaasPostRequest struct {
	ErrataList    []string `json:"errata_list"`
	ModifiedSince string   `json:"modified_since"`
	Page          int      `json:"page"`
}

type CpeMapping struct {
	Advisory     string
	CVEs         []string
	PackageToCpe map[string][]string
}

type updater struct{}

var c = cache.New(24*time.Hour, 30*time.Minute)
var rpmToSrpmMapping = mapRpmToSrpm

var vmaasURL = getEnv("VMAAS_URL", "https://webapp-vmaas-stable.1b13.insights.openshiftapps.com/api/v1")
var cpeMappingURL = getEnv("CPE_MAPPING", "https://www.redhat.com/security/data/metrics/rhsamapcpe.txt")

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func init() {
	vulnsrc.RegisterUpdater("redhat", &updater{})
}

func (u *updater) Update(datastore database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "RedHat").Info("Start fetching vulnerabilities")

	newTime := time.Now().UTC().Format(time.RFC3339)
	// rhsaSince - last time when security data was fetched from VMaaS
	// additionalAdv - list of advisories which have been missing in CPE
	// mapping file in previous run
	rhsaSince, additionalAdv, err := findKeyValue(datastore)
	if err != nil {
		return resp, err
	}

	// this file provides mapping between advisory and CPEs
	cpeMapping, err := getAdvisory2CpeMapping()
	if err != nil {
		return resp, err
	}

	allAdvisories, err := getAdvisories(rhsaSince, additionalAdv)
	if err != nil {
		return resp, err
	}
	additionalAdv = []string{}
	advisories := []Advisory{}
	for _, adv := range allAdvisories {
		if len(adv.PackageList) == 0 || len(adv.CveList) == 0 {
			log.WithField("Advisory", adv.Name).Debug("No packages or CVEs in advisory. Skipping...")
			continue
		}
		_, err := findAdvisory(cpeMapping, adv.Name)
		if err != nil {
			// The advisory is missing in mapping file.
			// The missing advisory will be stored in database and refreshed next time.
			additionalAdv = append(additionalAdv, adv.Name)
			log.WithField("Advisory", adv.Name).Debug("The advisory is not available in CPE mapping file.")

		} else {
			advisories = append(advisories, adv)
		}

	}
	log.WithFields(log.Fields{
		"items":   len(advisories),
		"updater": "RedHat",
	}).Debug("Start processing advisories")
	advChan := make(chan Advisory, len(advisories))
	vulnChan := make(chan []database.VulnerabilityWithAffected, len(advisories))
	for i := 0; i < 20; i++ {
		// parallel processing
		go parseAdvisoryWorker(cpeMapping, advChan, vulnChan)
	}

	// sort advisories to make processing faster
	sort.Slice(advisories, func(i, j int) bool {
		return len(advisories[i].PackageList)+len(advisories[i].CveList) > len(advisories[j].PackageList)+len(advisories[j].CveList)
	})
	for _, advisory := range advisories {
		advChan <- advisory
	}
	close(advChan)
	for i := 0; i < len(advisories); i++ {
		vulnerabilities := <-vulnChan
		resp.Vulnerabilities = append(resp.Vulnerabilities, vulnerabilities...)
	}
	close(vulnChan)

	log.WithFields(log.Fields{
		"items":          len(resp.Vulnerabilities),
		"updater":        "RedHat",
		"newUpdaterTime": newTime,
		"missingMapping": additionalAdv,
	}).Debug("Found new vulnerabilities")

	// save new timestamp to database
	resp.Flags = make(map[string]string)
	resp.Flags[updaterFlag] = newTime
	resp.Flags[additionalAdvFlag] = strings.Join(additionalAdv, ",")
	return resp, nil

}

func findKeyValue(datastore database.Datastore) (rhsaSince string, additionalAdvSlice []string, err error) {
	// Get the timestamp from last scan
	rhsaSince, ok, err := database.FindKeyValueAndRollback(datastore, updaterFlag)
	if err != nil {
		return "", []string{}, err
	}

	if !ok {
		rhsaSince = rhsaFirstTime
	}

	additionalAdv, ok, err := database.FindKeyValueAndRollback(datastore, additionalAdvFlag)
	if err != nil {
		return "", []string{}, err
	}
	if additionalAdv != "" {
		additionalAdvSlice = strings.Split(additionalAdv, ",")
	}
	return rhsaSince, additionalAdvSlice, nil
}

func getAdvisory2CpeMapping() (cpeMapping []CpeMapping, err error) {
	r, err := httputil.GetWithUserAgent(cpeMappingURL)
	if err != nil {
		log.WithError(err).Error("Could not download RedHat's CPE mapping file")
		return cpeMapping, commonerr.ErrCouldNotDownload
	}
	defer r.Body.Close()

	if !httputil.Status2xx(r) {
		log.WithField("StatusCode", r.StatusCode).Error("Failed to update RedHat")
		return cpeMapping, commonerr.ErrCouldNotDownload
	}

	cpeMappingBytes, _ := ioutil.ReadAll(r.Body)
	cpeMappingData := string(cpeMappingBytes)

	cpeMapping = parseCpeMapping(cpeMappingData)
	return
}

func getAdvisories(rhsaSince string, additionalAdvisories []string) (advisories []Advisory, err error) {

	// First fetch advisories which have been published since last update
	regularAdvUpdate, err := vmaasAdvisoryRequest([]string{"RHSA-.*"}, rhsaSince)
	if err != nil {
		return
	}
	log.WithField("items", len(regularAdvUpdate)).Debug("Found advisories in regular update.")
	if len(additionalAdvisories) == 0 {
		return regularAdvUpdate, nil
	}
	// Now fetch advisories which have been missing in cpe mapping during previous update
	log.WithField("Advisories", additionalAdvisories).Debug("Requesting additional advisories")
	additionalUpdate, err := vmaasAdvisoryRequest(additionalAdvisories, rhsaFirstTime)
	if err != nil {
		return
	}
	log.WithField("items", len(additionalUpdate)).Debug("Found advisories in additional update.")
	allAdvNames := make(map[string]bool)
	for _, adv := range regularAdvUpdate {
		advisories = append(advisories, adv)
		allAdvNames[adv.Name] = true
	}
	for _, adv := range additionalUpdate {
		if _, ok := allAdvNames[adv.Name]; !ok {
			advisories = append(advisories, adv)
			allAdvNames[adv.Name] = true
		}
	}
	return advisories, nil
}

func vmaasAdvisoryRequest(advList []string, rhsaSince string) (advisories []Advisory, err error) {
	currentPage := 1
	for {
		requestParams := VmaasPostRequest{
			ErrataList:    advList,
			ModifiedSince: rhsaSince,
			Page:          currentPage,
		}
		log.WithFields(log.Fields{
			"json": requestParams,
		}).Debug("Requesting data from VMaaS")
		// Fetch the update list.
		advisoriesURL := vmaasURL + "/errata"
		r, err := httputil.PostWithUserAgent(advisoriesURL, requestParams)
		if err != nil {
			log.WithError(err).Error("Could not download RedHat's update list")
			return advisories, commonerr.ErrCouldNotDownload
		}
		defer r.Body.Close()

		if !httputil.Status2xx(r) {
			log.WithField("StatusCode", r.StatusCode).Error("Failed to update RedHat")
			return advisories, commonerr.ErrCouldNotDownload
		}

		var rhsaData RHSAdata
		if err := json.NewDecoder(r.Body).Decode(&rhsaData); err != nil {
			return advisories, err
		}
		for advisoryName, advisory := range rhsaData.ErrataList {
			advisory.Name = advisoryName
			advisories = append(advisories, advisory)
		}
		currentPage++
		if rhsaData.Page == rhsaData.Pages || rhsaData.Pages == 0 {
			// last page
			break
		}
	}
	return advisories, nil
}

func parseAdvisoryWorker(cpeMapping []CpeMapping, advisory <-chan Advisory, vulnerabilities chan<- []database.VulnerabilityWithAffected) {
	for adv := range advisory {
		vuln := parseAdvisory(adv, cpeMapping)
		vulnerabilities <- vuln
	}
}

func parseCpeMapping(data string) []CpeMapping {
	var cpeMapping []CpeMapping
	lines := strings.Split(data, "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}
		// Format of line: RHSA-XXXX:YYYY CVE-XXXX-YY,CVE-XXXX-YZ CPE1,CPE2
		fields := strings.Split(line, " ")
		cpes := strings.Split(fields[2], ",")
		packages := parseCpePackage(cpes, fields[0])
		mappingItem := CpeMapping{
			Advisory:     fields[0],
			CVEs:         strings.Split(fields[1], ","),
			PackageToCpe: packages,
		}
		cpeMapping = append(cpeMapping, mappingItem)
	}
	return cpeMapping

}

// parseCpePackage - parse package names from CPE string
// example: cpe:/o:redhat:enterprise_linux:6::computenode/NetworkManager
//    - source package: NetworkManager
func parseCpePackage(cpes []string, advisory string) map[string][]string {
	packageCpeMap := make(map[string][]string)

	for _, cpe := range cpes {
		if strings.Count(cpe, "/") == 1 || cpe == "" {
			// text-only advisories
			continue
		}
		separatorIndex := strings.LastIndex(cpe, "/")
		packageName := cpe[separatorIndex+1:]
		packageCpeMap[packageName] = append(packageCpeMap[packageName], cpe[:separatorIndex])
	}
	return packageCpeMap
}

// parseAdvisory - parse advisory metadata and create new Vulnerabilities objects
func parseAdvisory(advisory Advisory, cpeMapping []CpeMapping) (vulnerabilities []database.VulnerabilityWithAffected) {
	if len(advisory.PackageList) == 0 || len(advisory.CveList) == 0 {
		// text-only advisories
		return
	}
	advisoryMapping, err := findAdvisory(cpeMapping, advisory.Name)
	if err != nil {
		log.WithFields(log.Fields{
			"advisory": advisory.Name,
			"updater":  "RedHat",
		}).Debug("No CPE mapping for advisory")
		return
	}

	for _, cve := range advisoryMapping.CVEs {
		packageMap := make(map[string]bool)
		vulnerability := database.VulnerabilityWithAffected{
			Vulnerability: database.Vulnerability{
				Name:        cve,
				Link:        cveURL + cve,
				Severity:    severity(advisory.Severity),
				Description: advisory.Name + " - " + advisory.Description,
			},
		}
		for _, nevra := range advisory.PackageList {
			rpmNevraObj := parseRpm(nevra)
			if rpmNevraObj.Arch != "x86_64" && rpmNevraObj.Arch != "noarch" {
				continue
			}

			srpm := rpmToSrpmMapping(nevra)
			cpes, ok := advisoryMapping.PackageToCpe[srpm.Name]
			if !ok {
				continue
			}

			for _, cpe := range cpes {
				epochVersionRelease := rpmNevraObj.EpochVersionRelease()
				key := rpmNevraObj.Name + epochVersionRelease + cpe
				ok := packageMap[key]
				if ok {
					// filter out duplicated features (arch specific)
					continue
				}
				p := database.AffectedFeature{
					FeatureName:     rpmNevraObj.Name,
					AffectedVersion: epochVersionRelease,
					FixedInVersion:  epochVersionRelease,
					FeatureType:     affectedType,
					Namespace: database.Namespace{
						Name:          cpe,
						VersionFormat: rpm.ParserName,
					},
				}

				packageMap[key] = true
				vulnerability.Affected = append(vulnerability.Affected, p)
			}

		}
		if len(vulnerability.Affected) > 0 {
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}
	return
}

// findAdvisory in list of advisories based on name
func findAdvisory(cpeMapping []CpeMapping, advisory string) (CpeMapping, error) {
	for _, item := range cpeMapping {
		if item.Advisory == advisory {
			return item, nil
		}
	}
	return CpeMapping{}, errors.New("No advisory in mapping file")
}

// mapRpmToSrpm based on Brew data
// Brew API is cached
func mapRpmToSrpm(rpmNevra string) SRPM {
	value, found := c.Get(rpmNevra)
	if !found {
		brew := brew.NewClient(brewHub)
		rpmObj := parseRpm(rpmNevra)
		rpmInfo := brew.GetRPMInfo(rpmObj.rpmName())
		buildInfo := brew.GetBuildInfo(rpmInfo.BuildID)

		srpm := toSRPM(buildInfo)
		c.Set(rpmNevra, srpm, cache.DefaultExpiration)
		return srpm
	} else {
		srpm := value.(SRPM)
		return srpm
	}

}

type NEVR struct {
	Name    string
	Epoch   *int
	Version string
	Release string
}

type RPM struct {
	NEVR
	Arch string
}

type SRPM struct {
	NEVR
}

func (rpm *RPM) rpmName() string {
	return fmt.Sprintf("%s-%s-%s.%s.rpm", rpm.Name, rpm.Version, rpm.Release, rpm.Arch)
}

func parseSrpm(name string) SRPM {
	r := regexp.MustCompile(`(.*)-(([0-9]+):)?([^-]+)-([^-]+)`)
	match := r.FindStringSubmatch(name)
	srpm := SRPM{}
	srpm.Name = match[1]
	srpm.Version = match[4]
	srpm.Release = match[5]

	if match[3] != "" {
		epoch, _ := strconv.Atoi(match[3])
		srpm.Epoch = &epoch
	}
	return srpm
}

func parseRpm(name string) RPM {
	r := regexp.MustCompile(`(.*)-(([0-9]+):)?([^-]+)-([^-]+)\.([a-z0-9_]+)`)
	match := r.FindStringSubmatch(name)
	rpm := RPM{}
	rpm.Name = match[1]
	rpm.Version = match[4]
	rpm.Release = match[5]
	rpm.Arch = match[6]
	if match[3] != "" {
		epoch, _ := strconv.Atoi(match[3])
		rpm.Epoch = &epoch
	}
	return rpm
}

func (rpm *RPM) EpochVersionRelease() string {
	if rpm.Epoch != nil {
		return fmt.Sprintf("%d:%s-%s", *rpm.Epoch, rpm.Version, rpm.Release)
	}
	return fmt.Sprintf("%s-%s", rpm.Version, rpm.Release)
}

func toSRPM(buildInfo brew.BuildInfo) SRPM {
	srpm := SRPM{}
	srpm.Name = buildInfo.Name
	srpm.Version = buildInfo.Version
	srpm.Release = buildInfo.Release
	srpm.Epoch = buildInfo.Epoch

	return srpm
}

func (rpm *RPM) toNVRA() string {
	return fmt.Sprintf("%s-%s-%s.%s", rpm.Name, rpm.Version, rpm.Release, rpm.Arch)
}

func (rpm *RPM) toNVR() string {
	return fmt.Sprintf("%s-%s-%s", rpm.Name, rpm.Version, rpm.Release)
}

func (srpm *SRPM) toNVR() string {
	return fmt.Sprintf("%s-%s-%s", srpm.Name, srpm.Version, srpm.Release)
}

func severity(sev string) database.Severity {
	switch strings.Title(sev) {
	case "Low":
		return database.LowSeverity
	case "Moderate":
		return database.MediumSeverity
	case "Important":
		return database.HighSeverity
	case "Critical":
		return database.CriticalSeverity
	default:
		log.Warningf("could not determine vulnerability severity from: %s.", sev)
		return database.UnknownSeverity
	}
}

func (u *updater) Clean() {}
