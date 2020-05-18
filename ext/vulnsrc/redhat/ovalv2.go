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

// ovalv2.go provides fetch/parsing/etc specific to version-2 oval
// (keeping separate for potential reuse)
package redhat

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/quay/clair/v3/database"
	"github.com/quay/clair/v3/ext/versionfmt/modulerpm"
	"github.com/quay/clair/v3/ext/versionfmt/rpm"
	"github.com/quay/clair/v3/pkg/commonerr"
	"github.com/quay/clair/v3/pkg/httputil"
	"github.com/quay/clair/v3/ext/vulnsrc"
	log "github.com/sirupsen/logrus"
)

const (
	PulpV2BaseURL            = "https://www.redhat.com/security/data/oval/v2/"
	PulpManifest             = "PULP_MANIFEST"
	DbManifestEntryKeyPrefix = "oval.v2.pulp.manifest.entry."
	DbLastAdvisoryDateKey    = "oval.v2.advisory.date.issued"
	DefaultLastAdvisoryDate  = "1970-01-01"          // literal date (in case no existing last advisory date is found)
	AdvisoryDateFormat       = "2006-01-02"          // 'magical reference date' for datetime format
	UpdaterFlag              = "RedHatOvalV2Updater"
	UpdaterFlagDateFormat    = "2006-01-02 15:04:05" // 'magical reference date' for datetime format
	AffectedType             = database.BinaryPackage
	CveURL                   = "https://access.redhat.com/security/cve/"
)

var SupportedArches = map[string]bool { "x86_64":true, "noarch":true }

func init() {
	vulnsrc.RegisterUpdater("ovalv2", &updater{})
}

func (u *updater) Clean() {}

func (u *updater) Update(datastore database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "RedHat").Info("Start fetching vulnerabilities")

	pulpManifestBody, err := FetchPulpManifest(PulpV2BaseURL + PulpManifest)
	if err != nil {
		log.Debug("Unable to fetch pulp manifest file: " + PulpV2BaseURL + PulpManifest)
		return resp, err
	}
	pulpManifestEntries := ParsePulpManifest(pulpManifestBody)

	// walk the set of pulpManifestEntries
	for _, manifestEntry := range pulpManifestEntries {
		// check if this entry has already been processed (based on its sha256 hash)
		if IsNewOrUpdatedManifestEntry(manifestEntry, datastore) {
			unprocessedAdvisories := []ParsedAdvisory{}
			// this is new/updated, process it now
			log.Debug("Found updated/new pulp manifest entry. Processing: " + manifestEntry.BzipPath)

			// unzip and read the bzip-compressed oval file into an xml string
			ovalXml, err := ReadBzipOvalFile(PulpV2BaseURL + manifestEntry.BzipPath)
			if err != nil {
				// log error and continue
				log.Error(err)
				continue
			}
			if (ovalXml == "") {
				log.Error("Cannot parse empty source oval doc")
				continue
			}
			//
			ovalDoc := OvalV2Document{}
			err = xml.Unmarshal([]byte(ovalXml), &ovalDoc)
			if err != nil {
				// log error and continue
				log.Error(err)
				continue
			}

			unprocessedAdvisories, err = GatherUnprocessedAdvisories(manifestEntry, ovalDoc, datastore)
			if err != nil {
				// log error and continue
				log.Error(err)
				continue
			}
			if len(unprocessedAdvisories) < 1 {
				log.Info("Successful update, no unprocessed advisories found.")
				continue
			}

			log.WithFields(log.Fields{
				"items":   len(unprocessedAdvisories),
				"updater": "RedHat",
			}).Debug("Start processing advisories")

			resp.Vulnerabilities = append(resp.Vulnerabilities, CollectVulnerabilities(unprocessedAdvisories, ovalDoc)...)

			// remember the bzip hash for this entry, so we don't re-process it again next time (if unchanged)
			DbUpdateManifestEntrySignature(manifestEntry, datastore)

		} else {
			// this pulp manifest entry has already been processed; log and skip it
			log.Debug("Pulp manifest entry unchanged since last seen. Skipping: " + manifestEntry.BzipPath)
		}
	
	}

	// update the resp flag with summary of found
	if len(resp.Vulnerabilities) > 0 {
		resp.FlagName = UpdaterFlag
		resp.FlagValue = time.Now().Format(UpdaterFlagDateFormat)
	} else {
		log.WithField("package", "Red Hat").Debug("no update")
	}

	return resp, nil
}

// gather any non-processed pulp manifest entry advisories
func GatherUnprocessedAdvisories(manifestEntry ManifestEntry, ovalDoc OvalV2Document, datastore database.Datastore) ([]ParsedAdvisory, error) {
	unprocessedAdvisories := []ParsedAdvisory{}
	
	// get all unprocessed advisories from the oval file
	foundAdvisories, err := ProcessAdvisoriesSinceLastDbUpdate(ovalDoc, datastore)
	if err != nil {
		// log error and continue
		log.Error(err)
		return unprocessedAdvisories, err
	} else {
		// append found advisories to the to-be-processed list
		unprocessedAdvisories = append(unprocessedAdvisories, foundAdvisories...)
	}

	return unprocessedAdvisories, nil
}

func CollectVulnerabilities(advisoryDefinitions []ParsedAdvisory, ovalDoc OvalV2Document) (vulnerabilities []database.VulnerabilityWithAffected) {
	// walk the provided set of advisory definitions
	for _, advisoryDefinition := range advisoryDefinitions {
		vulnerabilities = append(vulnerabilities, CollectVulnsForAdvisory(advisoryDefinition, ovalDoc)...)
	}
	return vulnerabilities
}

// get the set of vulns for the given advisory (full doc must also be passed, for the states/tests/objects references)
func CollectVulnsForAdvisory(advisoryDefinition ParsedAdvisory, ovalDoc OvalV2Document) (vulnerabilities []database.VulnerabilityWithAffected) {
	for _, cve := range advisoryDefinition.Metadata.Advisory.CveList {
		packageMap := make(map[string]bool)
		vulnerability := database.VulnerabilityWithAffected{
			Vulnerability: database.Vulnerability{
				Name:        cve.Value + " - " + ParseRhsaName(advisoryDefinition),
				Link:        CveURL + cve.Value,
				Severity:    GetSeverity(advisoryDefinition.Metadata.Advisory.Severity),
				Description: advisoryDefinition.Metadata.Description,
			},
		}
		packageList := GetPackageList(advisoryDefinition.Criteria, ovalDoc)
		for _, parsedRmpNvra := range packageList {
			if !IsArchSupported(parsedRmpNvra.Arch) {
				continue
			}
			key := parsedRmpNvra.Name + parsedRmpNvra.Evr
			ok := packageMap[key]
			if ok {
				// filter out duplicated features (arch specific)
				continue
			}
			packageMap[key] = true

			feature := database.AffectedFeature{
				FeatureName:     parsedRmpNvra.Name,
				AffectedVersion: parsedRmpNvra.Evr,
				FixedInVersion:  parsedRmpNvra.Evr,
				FeatureType:     AffectedType,
			}
			moduleNamespaces := ParseCriteriaForModuleNamespaces(advisoryDefinition.Criteria)
			if len(moduleNamespaces) > 0 {
				// modular rpm has namespace made of module_name:stream
				feature.Namespace = database.Namespace{
					Name:          moduleNamespaces[0],
					VersionFormat: modulerpm.ParserName,
				}
				vulnerability.Affected = append(vulnerability.Affected, feature)
			} else {
				// normal rpm uses CPE namespaces
				cpeNames, err := ParseCpeNamesFromAffectedCpeList(advisoryDefinition.Metadata.Advisory.AffectedCpeList)
				if err != nil {
					// log error and continue
					log.Error(err)
					continue
				}
				if len(cpeNames) == 0 {
					log.Warning(fmt.Sprintf("No CPE for: %s %s %s", parsedRmpNvra.Name, parsedRmpNvra.Evr, advisoryDefinition.Metadata.Title))
				}
				for _, cpe := range cpeNames {
					feature.Namespace = database.Namespace{
						Name:          cpe,
						VersionFormat: rpm.ParserName,
					}
					vulnerability.Affected = append(vulnerability.Affected, feature)
				}
			}

		}
		if len(vulnerability.Affected) > 0 {
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}
	return
}

// construct the vulnerability name(s) from the given advisory definition
func ConstructVulnerabilityNames(advisoryDefinition ParsedAdvisory) []string {
	rhsaName := ParseRhsaName(advisoryDefinition)
	var vulnNames []string
	cveNames := ParseCveNames(advisoryDefinition)
	for _, cveName := range cveNames {
		vulnNames = append(vulnNames, cveName + " - " + rhsaName)
	}
	return vulnNames
}

// construct the []VulnerabilityID set from the given advisory definition
func ConstructVulnerabilityIDs(advisoryDefinition ParsedAdvisory) []database.VulnerabilityID {
	var vulnIDs []database.VulnerabilityID
	rhsaName := ParseRhsaName(advisoryDefinition)
	cveNames := ParseCveNames(advisoryDefinition)
	for _, cveName := range cveNames {
		vulnID := database.VulnerabilityID{Name: cveName + " - " + rhsaName, Namespace: ParseVulnerabilityNamespace(advisoryDefinition)}
		vulnIDs = append(vulnIDs, vulnID)
	}
	return vulnIDs
}

// parse the CVE name(s) (e.g.: "CVE-2019-11249") from the given advisory definition
func ParseCveNames(advisoryDefinition ParsedAdvisory) []string {
	var cveNames []string
	for _, cve := range advisoryDefinition.Metadata.Advisory.CveList {
		cveNames = append(cveNames, cve.Value)
	}
	return cveNames
}

// parse the RHSA name (e.g.: "RHBA-2019:2794") from the given advisory definition
func ParseRhsaName(advisoryDefinition ParsedAdvisory) string {
	return strings.TrimSpace(advisoryDefinition.Metadata.Title[:strings.Index(advisoryDefinition.Metadata.Title, ": ")])
}

// parse the namespace from the given advisory definition
func ParseVulnerabilityNamespace(advisoryDefinition ParsedAdvisory) string {
	// use criteria parse result
	moduleNamespaces := ParseCriteriaForModuleNamespaces(advisoryDefinition.Criteria)
	if len(moduleNamespaces) > 0 {
		// use MODULE namespace
		return moduleNamespaces[0]
	} else {
		// use CPE namespace
		cpeNames, err := ParseCpeNamesFromAffectedCpeList(advisoryDefinition.Metadata.Advisory.AffectedCpeList)
		if err != nil {
			// log error and continue
			log.Error(err)
			return ""
		}
		if len(cpeNames) == 0 {
			// no namespace found
			return ""
		} else {
			return cpeNames[0]
		}
	}
}

func GetSeverity(sev string) database.Severity {
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

func extractAllCriterions(criteria OvalV2Criteria) []OvalV2Criterion {
    var criterions []OvalV2Criterion
    for _, criterion := range criteria.Criteria {
        // recursively append criteria contents
        criterions = append(criterions, extractAllCriterions(criterion)...)
    }
    for _, criterion := range criteria.Criterion {
        // append criterion
        criterions = append(criterions, criterion)
    }
    return criterions
}

func ParseNVRA(rpmName string) RpmNvra {
	// parse NVRA from RPM name
	// golang-1.6.3-2.el7.x86_64.rpm
	// Name        : golang
	// Version     : 1.6.3
	// Release     : 2.el7
	// Architecture: x86_64
	var regexRpmNVRA = regexp.MustCompile(`(.*/)*(.*)-(.*)-(.*?)\.([^.]*)(\.rpm)`)
	matches := regexRpmNVRA.FindStringSubmatch(rpmName)[2:6]
	rpmNvra := RpmNvra{matches[0], matches[1], matches[2], matches[3]}
	return rpmNvra
}

func IsRmpArchSupported(rpmName string) bool {
	return IsArchSupported(ParseNVRA(rpmName).Arch)
}

func IsArchSupported(arch string) bool {
	return SupportedArches[arch]
}

// parse affected_cpe_list (first entry from CPE list should not be used because it doesn't come from Advisory configuration)
func ParseCpeNamesFromAffectedCpeList(affectedCpeList OvalV2Cpe) ([]string, error) {
	var cpeNames []string
	if affectedCpeList.Cpe == nil || len(affectedCpeList.Cpe) < 2 {
		return cpeNames, errors.New("unparseable affected cpe list")
	}
	// parse and return any entries after the first cpe entry from the list
	for i := 1; i < len(affectedCpeList.Cpe); i++ {
		cpeNames = append(cpeNames, affectedCpeList.Cpe[i])
	}
	return cpeNames, nil
}

// parse affected_cpe_list (first entry from CPE list should not be used because it doesn't come from Advisory configuration)
func ParseCpeStructFromAffectedCpeList(affectedCpeList OvalV2Cpe) ([]string, error) {
	var cpeStructs []string
	if affectedCpeList.Cpe == nil || len(affectedCpeList.Cpe) < 2 {
		return cpeStructs, errors.New("unparseable affected cpe list")
	}
	// parse and return any entries after the first cpe entry from the list
	for i := 1; i < len(affectedCpeList.Cpe); i++ {
		cpeStructs = append(cpeStructs, affectedCpeList.Cpe[i])
	}
	return cpeStructs, nil
}

// parse cpe string
func ParseCpeName(cpeNameString string) CpeName {
	// cpe:/ {part} : {vendor} : {product} : {version} : {update} : {edition} : {language}
	// remove the "cpe:/" prelude and split the cpe name string into its components
	components := strings.Split(strings.Replace(cpeNameString, "cpe:/", "", 1), ":")
	// components slice must contain 7 elements; append empty string to any missing elements
	for i := len(components); i < 7; i++ {
		components = append(components, "")
	}
	return CpeName{
		Part:      components[0],
		Vendor:    components[1],
		Product:   components[2],
		Version:   components[3],
		Update:    components[4],
		Edition:   components[5],
		Language:  components[6],
	}
}

// get advisories from the given oval document which were issued since the last update (based on db value)
func ProcessAdvisoriesSinceLastDbUpdate(ovalDoc OvalV2Document, datastore database.Datastore) ([]ParsedAdvisory, error) {
	sinceDate := DbLookupLastAdvisoryDate(datastore)
	var advisories []ParsedAdvisory
	for _, definition := range ovalDoc.DefinitionSet.Definitions {
		// check if this entry has already been processed (based on its sha256 hash)
		if IsAdvisorySinceDate(sinceDate, definition.Metadata.Advisory.Issued.Date) {
			// this advisory was issued since the last advisory date in the database; add it
			advisories = append(advisories, ParseAdvisory(definition, ovalDoc))
		} else if IsAdvisorySameDate(sinceDate, definition.Metadata.Advisory.Issued.Date) {
			parsedAdvisory := ParseAdvisory(definition, ovalDoc)
			// advisory date is coarse (YYYY-MM-dd format) date only,
			// so it's possible that we'll see an advisory multiple times within the same day;
			// check the db in this case to be sure
			if (!DbLookupIsAdvisoryProcessed(parsedAdvisory, datastore)) {
				// this advisory id/version hasn't been processed yet; add it
				advisories = append(advisories, parsedAdvisory)
			}
		}
	}
	// debug-only info
	out, _ := xml.MarshalIndent(ovalDoc, " ", "  ")
	log.Debug(string(out))

	// update the db ky/value entry for the last advisory processed date (now, as coarse YYYY-MM-dd format)
	DbStoreLastAdvisoryDate(time.Now().Format(AdvisoryDateFormat), datastore)
	
	return advisories, nil
}

func ParseAdvisory(definition OvalV2AdvisoryDefinition, ovalDoc OvalV2Document) (ParsedAdvisory) {
	parsedAdvisory := ParsedAdvisory{
		Id: definition.Id, 
		Version: definition.Version, 
		Metadata: definition.Metadata,
		Criteria: definition.Criteria,
		PackageList: GetPackageList(definition.Criteria, ovalDoc),
	}
	return parsedAdvisory
}

func GetPackageList(criteria OvalV2Criteria, ovalDoc OvalV2Document) (parsedNvras []ParsedRmpNvra) {
	criterions := extractAllCriterions(criteria)
	for _, criterion := range criterions {
		// get package info
		parsedNvras = append(parsedNvras, FindPackageNvraInfo(criterion.TestRef, ovalDoc))
	}
	return
}

func FindPackageNvraInfo(testRefId string, ovalDoc OvalV2Document) ParsedRmpNvra {
	var parsedNvra ParsedRmpNvra
    for _, test := range ovalDoc.TestSet.Tests {
		if test.Id == testRefId {
			for _, obj := range ovalDoc.ObjectSet.Objects {
				if obj.Id == test.ObjectRef.Ref {
					parsedNvra.Name = obj.Name
				}
			}
			for _, state := range ovalDoc.StateSet.States {
				if (state.Id == test.StateRef.Ref) {
					parsedNvra.Evr = state.Evr.Value
					parsedNvra.Arch = state.Arch.Value
				}
			}
		}
	}
	return parsedNvra
}

// determine whether the given advisory date string is since the last update
func IsAdvisorySinceDate(sinceDate string, advisoryDate string) bool {
	if sinceDate == "" {
		sinceDate = DefaultLastAdvisoryDate
	}
	sinceTime, err := time.Parse(AdvisoryDateFormat, sinceDate)
    if err != nil {
		log.Error("error parsing date string: " + sinceDate)
		// if unable to parse date, treat as new advisory
		return true
	}
	advisoryTime, err := time.Parse(AdvisoryDateFormat, advisoryDate)
    if err != nil {
        log.Error("error parsing date string: " + advisoryDate)
		// if unable to parse date, treat as new advisory
		return true
	}
	return advisoryTime.After(sinceTime)
}

// determine whether the given advisory date string is the same as the last update
func IsAdvisorySameDate(sinceDate string, advisoryDate string) bool {
	if sinceDate == "" {
		sinceDate = DefaultLastAdvisoryDate
	}
	sinceTime, err := time.Parse(AdvisoryDateFormat, sinceDate)
    if err != nil {
        log.Error("error parsing date string: " + sinceDate)
		// if unable to parse date, treat as not same
		return false
	}
	advisoryTime, err := time.Parse(AdvisoryDateFormat, advisoryDate)
    if err != nil {
        log.Error("error parsing date string: " + advisoryDate)
		// if unable to parse date, treat as not same
		return false
	}
	return advisoryTime.Equal(sinceTime)
}

// lookup the last advisory date from db key/value table
func DbLookupLastAdvisoryDate(datastore database.Datastore) string {
	dbLastAdvisoryDate, ok, err := database.FindKeyValueAndRollback(datastore, DbLastAdvisoryDateKey)
	if err != nil {
		log.Error("Unable to lookup last advisory date, caused by: " + err.Error())
		// error while fetching record, use default
		return DefaultLastAdvisoryDate
	}
	if (ok == false || dbLastAdvisoryDate == "") {
		// no record found, use default
		return DefaultLastAdvisoryDate
	}
	// return the current db value
	return dbLastAdvisoryDate
}

// update the db key/value table with the given last advisory date
func DbStoreLastAdvisoryDate(lastAdvisoryDate string, datastore database.Datastore) {
	err := database.UpdateKeyValueAndCommit(datastore,
		DbLastAdvisoryDateKey, lastAdvisoryDate)
	if err != nil {
		// log the error and continue
		log.Error("Unable to store last advisory date, caused by: " + err.Error())
	}
}

// check the db key/value table for the given advisory's id, compare the stored 'version' value to current
func DbLookupIsAdvisoryProcessed(definition ParsedAdvisory, datastore database.Datastore) bool {
	// check the db to see if the associated vulnerability name is already stored
	vulnIds := ConstructVulnerabilityIDs(definition)
	foundVulns, err := database.FindVulnerabilitiesAndRollback(datastore, vulnIds)
	if err != nil {
		log.Error(err)
		// error during db lookup, treat advisory as unprocessed
		return false
	}
	if len(foundVulns) > 0 {
		// found a record, so this has already been processed
		return true
	} else {
		// no record found, so it hasn't been processed yet
		return false
	}
}

// update the db key/value table with the given manifest entry's signature
func DbUpdateManifestEntrySignature(manifestEntry ManifestEntry, datastore database.Datastore) {
	// store the latest sha256 hash for this entry
	err := database.UpdateKeyValueAndCommit(datastore,
		DbManifestEntryKeyPrefix + manifestEntry.BzipPath, manifestEntry.Signature)
	if err != nil {
		// log error and continue
		log.Error(err)
	}
}

// check the db key/value table to determine whether the given entry is new/updated
//   since the last time the manifest was processed
func IsNewOrUpdatedManifestEntry(manifestEntry ManifestEntry, datastore database.Datastore) bool {
	currentDbSignature, ok, err := database.FindKeyValueAndRollback(datastore,
		DbManifestEntryKeyPrefix + manifestEntry.BzipPath)
	if err != nil {
		// log the error and err on the side of treat-as-new/updated
		log.Error("Unable to store last advisory date, caused by: " + err.Error())
		return true
	}
	if ok == false {
		// no record found, so consider this entry as updated (since it hasn't been previously processed)
		return true
	}
	// consider the entry updated if the ManifestEntry.Signature value doesn't match the database record
	return manifestEntry.Signature != currentDbSignature
}

// fetch the PULP_MANIFEST file, return body as a string
func FetchPulpManifest(pulpManifestUrl string) (string, error) {
	resp, err := httputil.GetWithUserAgent(pulpManifestUrl)
	if err != nil {
		log.Error("Unable to fetch pulp manifest, caused by: " + err.Error())
		return "", err
	}
	defer resp.Body.Close()
	if !httputil.Status2xx(resp) {
		log.WithField("StatusCode", resp.StatusCode).Error("Unable to fetch pulp manifest")
		return "", commonerr.ErrCouldNotDownload
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error("Unable to read fetched pulp manifest, caused by: " + err.Error())
		return "", err
	}
	return string(body), err
}

// parse the PULP_MANIFEST file body
func ParsePulpManifest(pulpManifestBody string) []ManifestEntry {
	var manifestEntries []ManifestEntry
	if pulpManifestBody != "" {
		scanner := bufio.NewScanner(strings.NewReader(pulpManifestBody))
		for scanner.Scan() {
			entry, err := ParsePulpManifestLine(scanner.Text())
			if err == nil {
				// append the parsed manifest entry to the slice
				manifestEntries = append(manifestEntries, entry)
			} else {
				// log the error and continue
				log.Warn(err)
			}
		}
	}
	return manifestEntries
}

// return a ManifestEntry from parsing a single line from PULP_MANIFEST
func ParsePulpManifestLine(srcManifestLine string) (ManifestEntry, error) {
	entry := ManifestEntry{}
	if srcManifestLine == "" {
		return entry, errors.New("Cannot parse empty source manifest line")
	}
	data := strings.Split(srcManifestLine, ",")
	if len(data) < 3 {
		return entry, fmt.Errorf(
			"Not enough elements (%d of 3) in source manifest line: %s",
			len(data), srcManifestLine)
	}
	entry.BzipPath = data[0]
	entry.Signature = data[1]
	size, err := strconv.Atoi(data[2])
	if err != nil {
		log.Error("Unable to parse pulp manifest line, caused by: " + err.Error())
		entry.Size = 0
		return entry, err
	}
	entry.Size = size
	return entry, err
}

// decompress and read a bzip2-compressed oval file, return the xml content as string
func ReadBzipOvalFile(bzipOvalFile string) (string, error) {
	resp, err := httputil.GetWithUserAgent(bzipOvalFile)
	if err != nil {
		log.Error(err)
		return "", err
	}
	defer resp.Body.Close()
	if !httputil.Status2xx(resp) {
		log.WithField("StatusCode", resp.StatusCode).Error("Unable to fetch bzip-compressed oval file")
		return "", commonerr.ErrCouldNotDownload
	}
	// read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error(err)
		return "", err
	}
	// create a bzip2 reader from the response body bytes
	bzipreader := bzip2.NewReader(bytes.NewReader(body))
	if err != nil {
		log.Error(err)
		return "", err
	}
	// proceed with read
	content, readErr := ioutil.ReadAll(bzipreader)
	if readErr != nil {
		log.Error(readErr)
		return "", err
	}
	return string(content), nil
}

// parse one definition
func ParseCriteriaForModuleNamespaces(criteria OvalV2Criteria) ([]string) {
    var moduleNamespaces []string
	criterions := extractAllCriterions(criteria)
	// walk the criteria and add them
	for _, criterion := range criterions {
		// Module idm:DL1 is enabled
		var regexComment = regexp.MustCompile(`(Module )(.*)( is enabled)`)
		matches := regexComment.FindStringSubmatch(criterion.Comment)
		if matches != nil && len(matches) > 2 && matches[2] != "" {
			moduleNamespaces = append(moduleNamespaces, matches[2])
		}
		// moduleNamespaces = append(moduleNamespaces, criterion.Comment)
	}
    return moduleNamespaces
}

