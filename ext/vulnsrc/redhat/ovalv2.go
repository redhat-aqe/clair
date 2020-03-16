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
	"net/http"
	"strconv"
	"strings"

	"github.com/quay/clair/v3/database"
	log "github.com/sirupsen/logrus"
)

const (
	PulpV2BaseURL            = "https://www.redhat.com/security/data/oval/v2/"
	PulpManifest             = "PULP_MANIFEST"
	DbManifestEntryKeyPrefix = "oval.v2.pulp.manifest.entry."
	DbLastAdvisoryDateKey    = "oval.v2.advisory.date.issued"
	DefaultLastAdvisoryDate  = "1970-01-01"
)

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

type OvalDefinitions struct {
	XMLName xml.Name `xml:"oval_definitions"`
	Advisories  []*Advisory `xml:"definitions>definition>metadata>advisory"`
}

type Advisory struct {
    Issued    AdvisoryIssued     `xml:"issued"`
	Updated   AdvisoryUpdated    `xml:"updated"`
	Severity  string             `xml:"severity"`
	Cve       CveData            `xml:"cve"`
}

type AdvisoryIssued struct {
	XMLName  xml.Name  `xml:"issued"`
    Date     string    `xml:"date,attr"`
}

type AdvisoryUpdated struct {
	XMLName  xml.Name  `xml:"updated"`
    Date     string    `xml:"date,attr"`
}

type CveData struct {
	XMLName  xml.Name  `xml:"cve"`
    Cvss3    string    `xml:"cvss3,attr"`
    Cwe      string    `xml:"cwe,attr"`
	Href     string    `xml:"href,attr"`
	Public   string    `xml:"public,attr"`
}

func GetUnprocessedAdvisories(ovalDoc string, datastore database.Datastore) ([]Advisory, error) {
	dbLastAdvisoryDate := DbLookupLastAdvisoryDate(datastore)
	log.Debug(dbLastAdvisoryDate)
	if (ovalDoc == "") {
		return nil, errors.New("Cannot parse empty source oval doc")
	}
	//
	ovalDefinitions := &OvalDefinitions{}
	err := xml.Unmarshal([]byte(ovalDoc), &ovalDefinitions)
	if err != nil {
		panic(err)
	}
	var advisories []Advisory
	// walk the advisories and add any which are after the db last advisory date
	out, _ := xml.MarshalIndent(ovalDefinitions, " ", "  ")
	log.Debug(string(out))
	
	return advisories, nil
}

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

// update the db key/value table with the given manifest entry's signature 
func DbUpdateLastAdvisoryDate(lastAdvisoryDate string, datastore database.Datastore) {
	// store the latest sha256 hash for this entry
	err := database.UpdateKeyValueAndCommit(datastore, 
		DbLastAdvisoryDateKey, lastAdvisoryDate)
	if err != nil {
		log.Fatal(err)
	}
}

// process any non-processed pulp manifest entries
func ProcessPulpManifestEntries(manifestEntries []ManifestEntry, datastore database.Datastore) {
	for _, manifestEntry := range manifestEntries {
		// check if this entry has already been processed (based on its sha256 hash)
		if IsNewOrUpdatedManifestEntry(manifestEntry, datastore) {
			// this is a new unprocessed update, process it now
			DbUpdateManifestEntrySignature(manifestEntry, datastore)
		}
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
	resp, err := http.Get(pulpManifestUrl)
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
		return entry, errors.New(fmt.Sprintf(
			"Not enough elements (%d of 3) in source manifest line: %s",
			len(data), srcManifestLine))
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

func ReadBzipOvalFile(bzipOvalFile string) (string, error) {
	var stringbuilder strings.Builder
	resp, err := http.Get(bzipOvalFile)
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
