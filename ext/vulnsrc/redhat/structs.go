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

// structs.go provides structs used by the redhat package
// (keeping separate for organization/clarity)
package redhat

import (
	"encoding/xml"
)

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

type OvalV2Document struct {
	XMLName          xml.Name                      `xml:"oval_definitions"`
	DefinitionSet    OvalV2AdvisoryDefinitions     `xml:"definitions"`
	TestSet			 OvalV2Tests                   `xml:"tests"`
	ObjectSet	     OvalV2Objects                 `xml:"objects"`
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
	Title            string            `xml:"title"`
	Description      string            `xml:"description"`
	Advisory         OvalV2Advisory    `xml:"advisory"`
}

type OvalV2Advisory struct {
    Issued           OvalV2AdvisoryIssued     `xml:"issued"`
	Updated          OvalV2AdvisoryUpdated    `xml:"updated"`
	Severity         string                   `xml:"severity"`
	CveList          []OvalV2CveData          `xml:"cve"`
	AffectedCpeList  OvalV2Cpe                `xml:"affected_cpe_list"`
}

type OvalV2AdvisoryIssued struct {
    Date     string    `xml:"date,attr"`
}

type OvalV2AdvisoryUpdated struct {
    Date     string    `xml:"date,attr"`
}

type OvalV2CveData struct {
	XMLName  xml.Name  `xml:"cve"`
    Cvss3    string    `xml:"cvss3,attr"`
    Cwe      string    `xml:"cwe,attr"`
	Href     string    `xml:"href,attr"`
	Public   string    `xml:"public,attr"`
	Value    string    `xml:",chardata"`
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

type OvalV2Objects struct {
	XMLName     xml.Name              `xml:"objects"`
	Objects     []OvalV2RpmInfoObject `xml:"rpminfo_object"`
}

type OvalV2RpmInfoObject struct {
	Id          string                `xml:"id,attr"`
	Version     string                `xml:"version,attr"`
	Name        string                `xml:"name"`
}

type OvalV2States struct {
	XMLName     xml.Name              `xml:"states"`
	States      []OvalV2RpmInfoState  `xml:"rpminfo_state"`
}

type OvalV2RpmInfoState struct {
	Id          string                `xml:"id,attr"`
	Version     string                `xml:"version,attr"`
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
	CpeNamespaces     []string
}

type RpmNvra struct {
	Name     string
	Version  string
	Release  string
	Arch     string
}

type ParsedAdvisory struct {
	Id               string
	Version          string
	Metadata         OvalV2Metadata
	Criteria         OvalV2Criteria
	PackageList      []ParsedRmpNvra
}

type ParsedRmpNvra struct {
	Name     string
	Evr      string
	Arch     string
}
