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

package redhat

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/quay/clair/v3/database"
	log "github.com/sirupsen/logrus"
)

const (
	TestLastAdvisoryDate  = "2019-11-01"
)

func TestIsNewOrUpdatedManifestEntry(t *testing.T) {

	manifestEntry_1 := ManifestEntry{
		"RHEL8/ansible-2.8.oval.xml.bz2", "14a04f048080a246ef4e1d1c76e5beec12d16cbfd8013235f0ff2f88e4d78aed", 3755}
	manifestEntry_2 := ManifestEntry{
		"RHEL8/ansible-2.8.oval.xml.bz2", "320eeb4984a0678e4fa9a3f8421b87f2a57a2922cd4e3f582eb7cc735239ce72", 3755}
	type args struct {
		manifestEntry ManifestEntry
		datastore     database.Datastore
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"1", args{manifestEntry_1, newmockDatastore()}, false},
		{"2", args{manifestEntry_2, newmockDatastore()}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNewOrUpdatedManifestEntry(tt.args.manifestEntry, tt.args.datastore); got != tt.want {
				t.Errorf("IsNewOrUpdatedManifestEntry() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFetchPulpManifest(t *testing.T) {
	pwd, _ := os.Getwd()
	filePath := pwd + "/testdata/v2/PULP_MANIFEST"
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal("error reading " + filePath)
	} else {
		log.Debug("found " + filePath + ": " + string(content))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(string(content)))
	}))
	defer srv.Close()
	type args struct {
		pulpManifestUrl string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"1", args{string(srv.URL)}, string(content), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FetchPulpManifest(tt.args.pulpManifestUrl)
			if (err != nil) != tt.wantErr {
				t.Errorf("FetchPulpManifest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("FetchPulpManifest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReadBzipOvalFile(t *testing.T) {
	pwd, _ := os.Getwd()
	// bzip-compressed file (used for the httptest download endpoint)
	bzipFilePath := pwd + "/testdata/v2/ansible-2.8.oval.xml.bz2"
	bzipContent, err := ioutil.ReadFile(bzipFilePath)
	// uncompressed xml file (used for the test result comparison)
	xmlFilePath := pwd + "/testdata/v2/ansible-2.8.oval.xml"
	xmlContent, err := ioutil.ReadFile(xmlFilePath)
	if err != nil {
		log.Fatal("error reading " + xmlFilePath)
	} else {
		log.Debug("found " + xmlFilePath + ": " + string(xmlContent))
	}
	// httptest provides the bzip file download endpoint
	srv_1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(string(bzipContent)))
	}))
	defer srv_1.Close()
	// httptest provides the non-bzip file download endpoint
	srv_2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(string("ABCD1234")))
	}))
	defer srv_2.Close()
	type args struct {
		bzipOvalFile string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"given valid bzip2 file, expect success", args{string(srv_1.URL)}, string(xmlContent), false},
		{"given non-bzip2 file, expect error", args{string(srv_2.URL)}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadBzipOvalFile(tt.args.bzipOvalFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadBzipOvalFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ReadBzipOvalFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetUnprocessedAdvisories(t *testing.T) {
	pwd, _ := os.Getwd()
	xmlFilePath := pwd + "/testdata/v2/ansible-2.8.oval.xml"
	xmlContent, err := ioutil.ReadFile(xmlFilePath)
	if err != nil {
		log.Fatal("error reading " + xmlFilePath)
	}
	type args struct {
		ovalDoc    string
		sinceDate  string
	}
	tests := []struct {
		name      string
		args      args
		wantCount int
		wantErr   bool
	}{
		{"1", args{string(xmlContent), "2020-01-22"}, 1, false},
		{"2", args{string(xmlContent), "2019-10-25"}, 2, false},
		{"3", args{string(xmlContent), "2019-10-23"}, 3, false},
		{"4", args{string(xmlContent), "2019-08-21"}, 4, false},
		{"5", args{string(xmlContent), "2019-07-01"}, 5, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getAdvisoriesSince(tt.args.ovalDoc, tt.args.sinceDate, newmockDatastore())
			if (err != nil) != tt.wantErr {
				t.Errorf("getAdvisoriesSince() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantCount != len(got) {
				t.Errorf("getAdvisoriesSince() = %v, want %v", len(got), tt.wantCount)
			}
		})
	}
}

func TestDbLookupLastAdvisoryDate(t *testing.T) {
	type args struct {
		datastore database.Datastore
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"1", args{newmockDatastore()}, TestLastAdvisoryDate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DbLookupLastAdvisoryDate(tt.args.datastore); got != tt.want {
				t.Errorf("DbLookupLastAdvisoryDate() = %v, want %v", got, tt.want)
			}
		})
	}
}

type mockDatastore struct {
	database.MockDatastore

	keyValues map[string]string
}

type mockUpdaterSession struct {
	database.MockSession

	store      *mockDatastore
	copy       mockDatastore
	terminated bool
}

func copyDatastore(md *mockDatastore) mockDatastore {
	kv := map[string]string{
		DbManifestEntryKeyPrefix + "RHEL7/ansible-2.8.oval.xml.bz2": "b5a05dbe78f7d472f08bc4ad221d6018ce5e5ad32434f997fe395d54ebe21e65",
		DbManifestEntryKeyPrefix + "RHEL7/ansible-2.9.oval.xml.bz2": "109f1d47b6221333fce2d54052a7cdb9ef50bd29adf964c18f054f4aac62beaa",
		DbManifestEntryKeyPrefix + "RHEL8/ansible-2.8.oval.xml.bz2": "14a04f048080a246ef4e1d1c76e5beec12d16cbfd8013235f0ff2f88e4d78aed",
		DbManifestEntryKeyPrefix + "RHEL8/ansible-2.9.oval.xml.bz2": "6e6edbcaf0bb3bac108a796d7fb2d2c4f637f581d6c6d2bb8d0d0a87294d4460",
		DbLastAdvisoryDateKey: TestLastAdvisoryDate,
	}
	for key, value := range md.keyValues {
		kv[key] = value
	}

	return mockDatastore{
		keyValues: kv,
	}
}

func newmockDatastore() *mockDatastore {
	errSessionDone := errors.New("Session Done")
	md := &mockDatastore{
		keyValues: make(map[string]string),
	}

	md.FctBegin = func() (database.Session, error) {
		session := &mockUpdaterSession{
			store:      md,
			copy:       copyDatastore(md),
			terminated: false,
		}

		session.FctCommit = func() error {
			if session.terminated {
				return errSessionDone
			}
			session.store.keyValues = session.copy.keyValues
			session.terminated = true
			return nil
		}

		session.FctRollback = func() error {
			if session.terminated {
				return errSessionDone
			}
			session.terminated = true
			session.copy = mockDatastore{}
			return nil
		}

		session.FctUpdateKeyValue = func(key, value string) error {
			session.copy.keyValues[key] = value
			return nil
		}

		session.FctFindKeyValue = func(key string) (string, bool, error) {
			s, b := session.copy.keyValues[key]
			return s, b, nil
		}

		return session, nil
	}
	return md
}
