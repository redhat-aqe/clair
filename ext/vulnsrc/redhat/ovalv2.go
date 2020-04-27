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
)

var SupportedArches = map[string]bool { "x86_64":true, "noarch":true }

type updater struct{}

type ManifestEntry struct {
	// comma-delimited manifest entry line from PULP_MANIFEST
	// format:
	//  [rhel version]/[platform bz2 file],[file sha256sum],[file bytes]
	// e.g.:
	//  RHEL8/ansible-2.8.oval.xml.bz2,14a04f048080a246ef4e1d1c76e5beec12d16cbfd8013235f0ff2f88e4d78aed,3755
	BzipPath  string // RHEL8/ansible-2.8.oval.xml.bz2
	Signature string // 14a04f048080a246ef4e1d1c76e5beec12d16cbfd8013235f0ff2f88e4d78aed
	Size      int    // 3755
}

type OvalV2Definitions struct {
	XMLName xml.Name `xml:"oval_definitions"`
	DefinitionSet    OvalV2AdvisoryDefinitions     `xml:"definitions"`
	TestSet			 OvalV2Tests                   `xml:"tests"`
	StateSet         OvalV2States                  `xml:"states"`
}

type OvalV2AdvisoryDefinitions struct {
	Definitions      []OvalV2AdvisoryDefinition    `xml:"definition"`
}

type OvalV2AdvisoryDefinition struct {
	Id               string            `xml:"id,attr"`
	Version          string            `xml:"version,attr`
	Metadata         OvalV2Metadata    `xml:"metadata"`
	Criteria         OvalV2Criteria    `xml:"criteria"`
}

type OvalV2Metadata struct {
	Advisory         OvalV2Advisory    `xml:"advisory"`
}

type OvalV2Advisory struct {
    Issued           OvalV2AdvisoryIssued     `xml:"issued"`
	Updated          OvalV2AdvisoryUpdated    `xml:"updated"`
	Severity         string                   `xml:"severity"`
	Cve              OvalV2CveData            `xml:"cve"`
	AffectedCpeList  OvalV2Cpe                `xml:"affected_cpe_list"`
}

type OvalV2AdvisoryIssued struct {
    Date     string    `xml:"date,attr"`
}

type OvalV2AdvisoryUpdated struct {
    Date     string    `xml:"date,attr"`
}

type OvalV2CveData struct {
    Cvss3    string    `xml:"cvss3,attr"`
    Cwe      string    `xml:"cwe,attr"`
	Href     string    `xml:"href,attr"`
	Public   string    `xml:"public,attr"`
}

type OvalV2Cpe struct {
	Cpe      []string   `xml:"cpe"`
}

type CpeName struct {
	Part       string
	Vendor     string
	Product    string
	Version    string
	Update     string
	Edition    string
	Language   string
}

type OvalV2Criteria struct {
	Criterion   []OvalV2Criterion     `xml:"criterion"`
	Criteria    []OvalV2Criteria      `xml:"criteria"`
}

type OvalV2Criterion struct {
	XMLName     xml.Name              `xml:"criterion"`
	Comment     string                `xml:"comment,attr"`
	TestRef     string                `xml:"test_ref,attr"`
}

type OvalV2Tests struct {
	XMLName     xml.Name              `xml:"tests"`
	Tests       []OvalV2RpmInfoTest   `xml:"rpminfo_test"`
}

type OvalV2RpmInfoTest struct {
	Comment     string                `xml:"comment,attr"`
	Id          string                `xml:"id,attr"`
	ObjectRef   RpmInfoTestObjectRef  `xml:"object"`
	StateRef    RpmInfoTestStateRef   `xml:"state"`
}

type RpmInfoTestObjectRef struct {
	Ref   string                `xml:"object_ref,attr"`
}

type RpmInfoTestStateRef struct {
	Ref    string                `xml:"state_ref,attr"`
}

type OvalV2States struct {
	XMLName     xml.Name              `xml:"states"`
	States      []OvalV2RpmInfoState  `xml:"rpminfo_state"`
}

type OvalV2RpmInfoState struct {
	Id          string                `xml:"id,attr"`
	Version     string                `xml:"versin,attr"`
	Arch        RpmInfoStateChild     `xml:"arch"`
	Evr         RpmInfoStateChild     `xml:"evr"`
}

type RpmInfoStateChild struct {
	DataType    string                `xml:"datatype,attr"`
	Operation   string                `xml:"operation,attr"`
	Value       string                `xml:",chardata"`
}

type OvalV2DefinitionNamespaces struct {
	ModuleNamespaces  []string
	CpeNamespaces     []CpeName
}

type RpmNvra struct {
	Name     string
	Version  string
	Release  string
	Arch     string
}

func (u *updater) Update(datastore database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "RedHat").Info("Start fetching vulnerabilities")

	pulpManifestBody, err := FetchPulpManifest(PulpV2BaseURL + PulpManifest)
	if err != nil {
		log.Debug("Unable to fetch pulp manifest file: " + PulpV2BaseURL + PulpManifest)
		return resp, err
	}
	pulpManifestEntries := ParsePulpManifest(pulpManifestBody)

	unprocessedAdvisories, err := GatherUnprocessedPulpManifestAdvisories(pulpManifestEntries, datastore)
	if err != nil {
		// log error and continue
		log.Error(err)
	}
	if len(unprocessedAdvisories) < 1 {
		log.Info("Successful update, no unprocessed advisories found.")
		return resp, nil
	}

	log.WithFields(log.Fields{
		"items":   len(unprocessedAdvisories),
		"updater": "RedHat",
	}).Debug("Start processing advisories")

	resp.Vulnerabilities = append(resp.Vulnerabilities, CollectVulnerabilities()...)

	// update the resp flag with summary of found
	if len(unprocessedAdvisories) > 0 {
		resp.FlagName = UpdaterFlag
		resp.FlagValue = time.Now().Format(UpdaterFlagDateFormat)
	} else {
		log.WithField("package", "Red Hat").Debug("no update")
	}

	return resp, nil
}

func CollectVulnerabilities() (vulnerabilities []database.VulnerabilityWithAffected) {
	// TODO: restore impl (removed for refactor)
	return vulnerabilities
}

// TODO: refactor this out to group unprocessed advisories by menifest entry
// gather any non-processed pulp manifest entry advisories
func GatherUnprocessedPulpManifestAdvisories(manifestEntries []ManifestEntry, datastore database.Datastore) ([]OvalV2AdvisoryDefinition, error) {
	unprocessedAdvisories := []OvalV2AdvisoryDefinition{}
	for _, manifestEntry := range manifestEntries {
		// check if this entry has already been processed (based on its sha256 hash)
		if IsNewOrUpdatedManifestEntry(manifestEntry, datastore) {
			// this is new/updated, process it now
			log.Debug("Found updated/new pulp manifest entry. Processing: " + manifestEntry.BzipPath)
			// unzip and read the bzip-compressed oval file into a string
			ovalList, err := ReadBzipOvalFile(PulpV2BaseURL + manifestEntry.BzipPath)
			if err != nil {
				// log error and continue
				log.Error(err)
				continue
			}
			// get all unprocessed advisories from the oval file
			foundAdvisories, err := GetAdvisoriesSinceLastDbUpdate(ovalList, datastore)
			if err != nil {
				// log error and continue
				log.Error(err)
				continue
			} else {
				// append found advisories to the to-be-processed list
				unprocessedAdvisories = append(unprocessedAdvisories, foundAdvisories...)
				// remember the bzip hash for this entry, so we don't re-process it again next time (if unchanged)
				DbUpdateManifestEntrySignature(manifestEntry, datastore)
			}
		} else {
			// this pulp manifest entry has already been processed; log and skip it
			log.Debug("Pulp manifest entry unchanged since last seen. Skipping: " + manifestEntry.BzipPath)
			continue
		}
	}

	return unprocessedAdvisories, nil
}

// parent call to parse entire doc
func ParseDefinitionNamespaces(ovalDefinitionsXml string) []OvalV2DefinitionNamespaces {
	ovalV2DefinitionNamespaces := []OvalV2DefinitionNamespaces{}
	ovalDefinitions := OvalV2Definitions{}
	err := xml.Unmarshal([]byte(ovalDefinitionsXml), &ovalDefinitions)
	if err != nil {
		panic(err)
	}
	// for _, definition := range ovalDefinitions.Definitions {
	for _, definition := range ovalDefinitions.DefinitionSet.Definitions {
		criteriaNs, err := ParseCriteriaForModuleNamespaces(definition)
		if err != nil {
			// log error and continue
			log.Error(err)
		}
		cpeNames, err := ParseParseCpeNameFromAffectedCpeList(definition.Metadata.Advisory.AffectedCpeList)
		if err != nil {
			// log error and continue
			log.Error(err)
		}
		ovalV2DefinitionNamespace := OvalV2DefinitionNamespaces{criteriaNs, cpeNames}
		ovalV2DefinitionNamespaces = append(ovalV2DefinitionNamespaces, ovalV2DefinitionNamespace)
	}
	return ovalV2DefinitionNamespaces
}

// parse one definition
func ParseCriteriaForModuleNamespaces(ovalAdvisoryDefinition OvalV2AdvisoryDefinition) ([]string, error) {
    var moduleNamespaces []string
	criteria := extractAllCriterions(ovalAdvisoryDefinition.Criteria)
	// walk the criteria and add them
	for _, criterion := range criteria {
		// Module idm:DL1 is enabled
		var regexComment = regexp.MustCompile(`(Module )(.*)( is enabled)`)
		matches := regexComment.FindStringSubmatch(criterion.Comment)
		if matches != nil && len(matches) > 2 && matches[2] != "" {
			moduleNamespaces = append(moduleNamespaces, matches[2])
		}
		// moduleNamespaces = append(moduleNamespaces, criterion.Comment)
	}
    return moduleNamespaces, nil
}

func ParseCriteriaForStateData(ovalAdvisoryDefinition OvalV2AdvisoryDefinition, ovalV2Definitions OvalV2Definitions) []OvalV2RpmInfoState {
	var stateData []OvalV2RpmInfoState 
	criteria := extractAllCriterions(ovalAdvisoryDefinition.Criteria)
	// walk the criteria and add them
    for _, criterion := range criteria {
		stateData = append(stateData, FindRelatedStateData(criterion.TestRef, ovalV2Definitions)...)
	}
	return stateData
}

func FindRelatedStateData(testRef string, ovalV2Definitions OvalV2Definitions) []OvalV2RpmInfoState {
	var stateData []OvalV2RpmInfoState
    for _, test := range ovalV2Definitions.TestSet.Tests {
		if test.Id == testRef {
			stateRefId := test.StateRef.Ref
			for _, state := range ovalV2Definitions.StateSet.States {
				if (state.Id == stateRefId) {
					stateData = append(stateData, state)
				}
			}
		}
	}
	return stateData
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
func ParseParseCpeNameFromAffectedCpeList(affectedCpeList OvalV2Cpe) ([]CpeName, error) {
	cpeNames := []CpeName{}
	if affectedCpeList.Cpe == nil || len(affectedCpeList.Cpe) < 2 {
		return cpeNames, errors.New("unparseable affected cpe list")
	}
	// parse and return any entries after the first cpe entry from the list
	for i := 1; i < len(affectedCpeList.Cpe); i++ {
		cpeNames = append(cpeNames, ParseCpeName(affectedCpeList.Cpe[i]))
	}
	return cpeNames, nil
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

// get advisories from the given oval xml which were issued since the last update (based on db value)
func GetAdvisoriesSinceLastDbUpdate(ovalDoc string, datastore database.Datastore) ([]OvalV2AdvisoryDefinition, error) {
	if (ovalDoc == "") {
		return nil, errors.New("Cannot parse empty source oval doc")
	}
	//
	ovalDefinitions := OvalV2Definitions{}
	err := xml.Unmarshal([]byte(ovalDoc), &ovalDefinitions)
	if err != nil {
		panic(err)
	}
	sinceDate := DbLookupLastAdvisoryDate(datastore)
	var advisories []OvalV2AdvisoryDefinition
	for _, definition := range ovalDefinitions.DefinitionSet.Definitions {
		// check if this entry has already been processed (based on its sha256 hash)
		if IsAdvisorySinceDate(sinceDate, definition.Metadata.Advisory.Issued.Date) {
			// this advisory was issued since the last advisory date in the database; add it
			advisories = append(advisories, definition)
		} else if IsAdvisorySameDate(sinceDate, definition.Metadata.Advisory.Issued.Date) {
			// advisory date is coarse (YYYY-MM-dd format) date only,
			// so it's possible that we'll see an advisory multiple times within the same day;
			// check the db in this case to be sure
			if (!DbLookupIsAdvisoryProcessed(definition.Id, definition.Version, datastore)) {
				// this advisory id/version hasn't been processed yet; add it
				advisories = append(advisories, definition)
				// update the db ky/value entry for this advisory
				DbStoreAdvisoryProcessed(definition.Id, definition.Version, datastore)
			}
		}
	}
	// debug-only info
	out, _ := xml.MarshalIndent(ovalDefinitions, " ", "  ")
	log.Debug(string(out))

	// update the db ky/value entry for the last advisory processed date (now, as coarse YYYY-MM-dd format)
	DbStoreLastAdvisoryDate(time.Now().Format(AdvisoryDateFormat), datastore)
	
	return advisories, nil
}

// determine whether the given advisory date string is since the last update
func IsAdvisorySinceDate(sinceDate string, advisoryDate string) bool {
	sinceTime, err := time.Parse(AdvisoryDateFormat, sinceDate)
    if err != nil {
        log.Fatal("error parsing date string: " + sinceDate)
	}
	advisoryTime, err := time.Parse(AdvisoryDateFormat, advisoryDate)
    if err != nil {
        log.Fatal("error parsing date string: " + advisoryDate)
	}
	return advisoryTime.After(sinceTime)
}

// determine whether the given advisory date string is the same as the last update
func IsAdvisorySameDate(sinceDate string, advisoryDate string) bool {
	sinceTime, err := time.Parse(AdvisoryDateFormat, sinceDate)
    if err != nil {
        log.Fatal("error parsing date string: " + sinceDate)
	}
	advisoryTime, err := time.Parse(AdvisoryDateFormat, advisoryDate)
    if err != nil {
        log.Fatal("error parsing date string: " + advisoryDate)
	}
	return advisoryTime.Equal(sinceTime)
}

// lookup the last advisory date from db key/value table
func DbLookupLastAdvisoryDate(datastore database.Datastore) string {
	dbLastAdvisoryDate, ok, err := database.FindKeyValueAndRollback(datastore, DbLastAdvisoryDateKey)
	if err != nil {
		log.Fatal(err)
	}
	if ok == false {
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
		log.Fatal(err)
	}
}

// check the db key/value table for the given advisory's id, compare the stored 'version' value to current
func DbLookupIsAdvisoryProcessed(id string, currentVersion string, datastore database.Datastore) bool {
	foundAdvisoryVersion, ok, err := database.FindKeyValueAndRollback(datastore, id)
	if err != nil {
		log.Fatal(err)
	}
	if ok == false {
		// no record found, so assume it hasn't been processed
		return false
	}
	// compare the found version to the current version
	return currentVersion == foundAdvisoryVersion
}

// update the db key/value table with the given last advisory date
func DbStoreAdvisoryProcessed(id string, currentVersion string, datastore database.Datastore) {
	err := database.UpdateKeyValueAndCommit(datastore,
		id, currentVersion)
	if err != nil {
		log.Fatal(err)
	}
}

// update the db key/value table with the given manifest entry's signature
func DbUpdateManifestEntrySignature(manifestEntry ManifestEntry, datastore database.Datastore) {
	// store the latest sha256 hash for this entry
	err := database.UpdateKeyValueAndCommit(datastore,
		DbManifestEntryKeyPrefix + manifestEntry.BzipPath, manifestEntry.Signature)
	if err != nil {
		log.Fatal(err)
	}
}

// check the db key/value table to determine whether the given entry is new/updated
//   since the last time the manifest was processed
func IsNewOrUpdatedManifestEntry(manifestEntry ManifestEntry, datastore database.Datastore) bool {
	currentDbSignature, ok, err := database.FindKeyValueAndRollback(datastore,
		DbManifestEntryKeyPrefix + manifestEntry.BzipPath)
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
	}
	entry.Size = size
	return entry, err
}

// decompress and read a bzip2-compressed oval file, return the xml content as string
func ReadBzipOvalFile(bzipOvalFile string) (string, error) {
	var stringbuilder strings.Builder
	resp, err := httputil.GetWithUserAgent(bzipOvalFile)
	if err != nil {
		log.Error(err)
		return "", err
	}
	defer resp.Body.Close()
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
	// only proceed with read if no errors so far
	if err == nil {
		content, readErr := ioutil.ReadAll(bzipreader)
		if readErr != nil {
			log.Error(readErr)
			return "", err
		}
		stringbuilder.WriteString(string(content))
	}
	return stringbuilder.String(), err
}
