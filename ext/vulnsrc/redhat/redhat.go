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
	"regexp"
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
	rhsaFirstTime = "2000-01-01T01:01:01+02:00"
	vmaasURL      = "https://webapp-vmaas-stable.1b13.insights.openshiftapps.com/api/v1"
	cpeMapping    = "https://www.redhat.com/security/data/metrics/rhsamapcpe.txt"
	cveURL        = "https://access.redhat.com/security/cve/"
	updaterFlag   = "redHatUpdater"
	affectedType  = database.BinaryPackage
	brewHub       = "http://brewhub.engineering.redhat.com/brewhub"
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

func init() {
	vulnsrc.RegisterUpdater("redhat", &updater{})
}

func (u *updater) Update(datastore database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "RedHat").Info("Start fetching vulnerabilities")

	// Get the timestamp from last scan
	flagValue, ok, err := database.FindKeyValueAndRollback(datastore, updaterFlag)
	if err != nil {
		return resp, err
	}
	timeNow := time.Now()
	newTime := timeNow.Format(time.RFC3339)
	rhsaSince := rhsaFirstTime
	if ok {
		rhsaSince = flagValue
	}
	currentPage := 1
	var advisories []Advisory

	for {
		requestParames := VmaasPostRequest{
			ErrataList:    []string{"RHSA-.*"},
			ModifiedSince: rhsaSince,
			Page:          currentPage,
		}
		// Fetch the update list.
		advisoriesURL := vmaasURL + "/errata/"
		r, err := httputil.PostWithUserAgent(advisoriesURL, requestParames)
		if err != nil {
			log.WithError(err).Error("Could not download RedHat's update list")
			return resp, commonerr.ErrCouldNotDownload
		}
		defer r.Body.Close()

		if !httputil.Status2xx(r) {
			log.WithField("StatusCode", r.StatusCode).Error("Failed to update RedHat")
			return resp, commonerr.ErrCouldNotDownload
		}

		var rhsaData RHSAdata
		if err := json.NewDecoder(r.Body).Decode(&rhsaData); err != nil {
			return resp, err
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

	r, err := httputil.GetWithUserAgent(cpeMapping)
	if err != nil {
		log.WithError(err).Error("Could not download RedHat's CPE mapping file")
		return resp, commonerr.ErrCouldNotDownload
	}
	defer r.Body.Close()

	if !httputil.Status2xx(r) {
		log.WithField("StatusCode", r.StatusCode).Error("Failed to update RedHat")
		return resp, commonerr.ErrCouldNotDownload
	}

	cpeMappingBytes, _ := ioutil.ReadAll(r.Body)
	cpeMappingData := string(cpeMappingBytes)

	cpeMapping := parseCpeMapping(cpeMappingData)

	advChan := make(chan Advisory, len(advisories))
	vulnChan := make(chan []database.VulnerabilityWithAffected, len(advisories))
	for i := 0; i < 20; i++ {
		// parallel processing
		go parseAdvisoryWorker(cpeMapping, advChan, vulnChan)
	}
	for _, advisory := range advisories {
		advChan <- advisory
	}
	close(advChan)
	for i := 0; i < len(advisories); i++ {
		vulnerabilities := <-vulnChan
		resp.Vulnerabilities = append(resp.Vulnerabilities, vulnerabilities...)
	}
	close(vulnChan)

	if len(resp.Vulnerabilities) > 0 {
		log.WithFields(log.Fields{
			"items":   len(resp.Vulnerabilities),
			"updater": "RedHat",
		}).Debug("Found new vulnerabilities")
	}

	// save new timestamp to database
	resp.FlagName = updaterFlag
	resp.FlagValue = newTime
	return resp, nil

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
		vulnerability := database.VulnerabilityWithAffected{
			Vulnerability: database.Vulnerability{
				Name:        cve,
				Link:        cveURL + cve,
				Severity:    severity(advisory.Severity),
				Description: advisory.Description,
			},
		}
		for _, nevra := range advisory.PackageList {
			srpm := rpmToSrpmMapping(nevra)
			cpes, ok := advisoryMapping.PackageToCpe[srpm.Name]
			if !ok {
				continue
			}

			rpmNevraObj := parseRpm(nevra)
			for _, cpe := range cpes {
				p := database.AffectedFeature{
					FeatureName:     rpmNevraObj.Name,
					AffectedVersion: rpmNevraObj.Version + "-" + rpmNevraObj.Release,
					FixedInVersion:  rpmNevraObj.Version + "-" + rpmNevraObj.Release,
					FeatureType:     affectedType,
					Namespace: database.Namespace{
						Name:          cpe,
						VersionFormat: rpm.ParserName,
					},
				}
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
