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
	"encoding/xml"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/versionfmt/rpm"
	"github.com/coreos/clair/ext/vulnsrc"
	"github.com/coreos/clair/pkg/commonerr"
	"github.com/coreos/clair/pkg/httputil"
)

const (
	rhsaFirstTime    = "2000-01-001T01:01:01+02:00"
	vmaasURL         = "https://webapp-vmaas-stable.1b13.insights.openshiftapps.com/api/v1"
	cveCPEMappingURL = "https://www.redhat.com/security/data/metrics/cvemap.xml"
	cveURL           = "https://access.redhat.com/security/cve/"
	updaterFlag      = "redHatUpdater"
	affectedType     = database.AffectBinaryPackage
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

type NVRA struct {
	Name    string
	Version string
	Release string
	Arch    string
}

type VmaasPostRequest struct {
	ErrataList    []string `json:"errata_list"`
	ModifiedSince string   `json:"modified_since"`
	Page          int      `json:"page"`
}

type Vulnerability struct {
	XMLName        xml.Name `xml:"Vulnerability"`
	Text           string   `xml:",chardata"`
	Name           string   `xml:"name,attr"`
	ThreatSeverity string   `xml:"ThreatSeverity"`
	PublicDate     string   `xml:"PublicDate"`
	Bugzilla       struct {
		Text string `xml:",chardata"`
		ID   string `xml:"id,attr"`
		URL  string `xml:"url,attr"`
		Lang string `xml:"lang,attr"`
	} `xml:"Bugzilla"`
	AffectedRelease []struct {
		Text        string `xml:",chardata"`
		Cpe         string `xml:"cpe,attr"`
		ProductName string `xml:"ProductName"`
		ReleaseDate string `xml:"ReleaseDate"`
		Advisory    struct {
			Text string `xml:",chardata"`
			Type string `xml:"type,attr"`
			URL  string `xml:"url,attr"`
		} `xml:"Advisory"`
		Package struct {
			Text string `xml:",chardata"`
			Name string `xml:"name,attr"`
		} `xml:"Package"`
	} `xml:"AffectedRelease"`
	UpstreamFix string `xml:"UpstreamFix"`
}

type Cvemap struct {
	Vulnerability []Vulnerability
}

type updater struct{}

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

	r, err := httputil.GetWithUserAgent(cveCPEMappingURL)
	if err != nil {
		log.WithError(err).Error("Could not download RedHat's CVE mapping file")
		return resp, commonerr.ErrCouldNotDownload
	}
	defer r.Body.Close()

	if !httputil.Status2xx(r) {
		log.WithField("StatusCode", r.StatusCode).Error("Failed to update RedHat")
		return resp, commonerr.ErrCouldNotDownload
	}

	var cveCpeMapping Cvemap
	if err := xml.NewDecoder(r.Body).Decode(&cveCpeMapping); err != nil {
		return resp, err
	}

	for _, advisory := range advisories {
		vulnerabilities := parseAdvisory(advisory, cveCpeMapping)
		resp.Vulnerabilities = append(resp.Vulnerabilities, vulnerabilities...)
	}

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

// parseAdvisory - parse advisory metadata and create new Vulnerabilities objects
func parseAdvisory(advisory Advisory, cveCpeMapping Cvemap) (vulnerabilities []database.VulnerabilityWithAffected) {
	for _, cve := range advisory.CveList {
		namespace := "unknown"
		var cveToCpe Vulnerability
		for _, cveMappingItem := range cveCpeMapping.Vulnerability {
			if cveMappingItem.Name == cve {
				cveToCpe = cveMappingItem
				break
			}
		}
		vulnerability := database.VulnerabilityWithAffected{
			Vulnerability: database.Vulnerability{
				Name:        cve,
				Link:        cveURL + cve,
				Severity:    severity(advisory.Severity),
				Description: advisory.Description,
			},
		}
		for _, nvra := range advisory.PackageList {
			parsedNVRA := parseNVRA(nvra)
			for _, cveAdvisory := range cveToCpe.AffectedRelease {
				if cveAdvisory.Advisory.Text == advisory.Name && parsedNVRA.nvr() == cveAdvisory.Package.Text {
					namespace = cveAdvisory.Cpe
					break
				}
			}
			// Once CPEs will be publicly available in RH's images we can use
			// CPEs directly instead of centos:version
			// To avoid false positives we need to filter only RHEL products
			if strings.HasPrefix(namespace, "cpe:/o:redhat:enterprise_linux:7") {
				namespace = "rhel:7"
			} else if strings.HasPrefix(namespace, "cpe:/o:redhat:enterprise_linux:6") {
				namespace = "rhel:6"
			} else {
				continue
			}
			p := database.AffectedFeature{
				FeatureName:     parsedNVRA.Name,
				AffectedVersion: parsedNVRA.Version + "-" + parsedNVRA.Release,
				FixedInVersion:  parsedNVRA.Version + "-" + parsedNVRA.Release,
				AffectedType:    affectedType,
				Namespace: database.Namespace{
					Name:          namespace,
					VersionFormat: rpm.ParserName,
				},
			}
			vulnerability.Affected = append(vulnerability.Affected, p)
		}
		if len(vulnerability.Affected) > 0 {
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}
	return
}

// parseNVRA - parse {name}-{version}-{release}.{arch}
func parseNVRA(nvra string) NVRA {
	var parsedNVRA NVRA
	archIndex := strings.LastIndex(nvra, ".")
	parsedNVRA.Arch = nvra[archIndex+1:]

	releaseIndex := strings.LastIndex(nvra[:archIndex], "-")
	parsedNVRA.Release = nvra[releaseIndex+1 : archIndex]

	versionIndex := strings.LastIndex(nvra[:releaseIndex], "-")
	parsedNVRA.Version = nvra[versionIndex+1 : releaseIndex]

	parsedNVRA.Name = nvra[:versionIndex]

	return parsedNVRA
}
func (nvra *NVRA) nvr() string {
	return nvra.Name + "-" + nvra.Version + "-" + nvra.Release
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
