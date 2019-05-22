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

package brew

type BuildInfo struct {
	PackageName string `xmlrpc:"package_name"`
	Epoch       *int   `xmlrpc:"epoch"`
	Version     string `xmlrpc:"version"`
	NVR         string `xmlrpc:"nvr"`
	Name        string `xmlrpc:"name"`
	VolumeName  string `xmlrpc:"volume_name"`
	Release     string `xmlrpc:"release"`
}

type Extra struct {
	Submitter           string `xmlrpc:"submitter"`
	Image               Image  `xmlrpc:"image"`
	ContainerKojiTaskID int64  `xmlrpc:"container_koji_task_id"`
}

type Image struct {
	MediaTypes        []string                    `xmlrpc:"media_types"`
	Help              interface{}                 `xmlrpc:"help"`
	Index             Index                       `xmlrpc:"index"`
	Autorebuild       bool                        `xmlrpc:"autorebuild"`
	Isolated          bool                        `xmlrpc:"isolated"`
	ParentBuildID     int64                       `xmlrpc:"parent_build_id"`
	ParentImageBuilds map[string]ParentImageBuild `xmlrpc:"parent_image_builds"`
}

type Index struct {
	Pull    []string `xmlrpc:"pull"`
	Digests Digests  `xmlrpc:"digests"`
	Tags    []string `xmlrpc:"tags"`
}

type Digests struct {
	ApplicationVndDockerDistributionManifestListV2xmlrpc string `xmlrpc:"application/vnd.docker.distribution.manifest.list.v2+xmlrpc"`
}

type ParentImageBuild struct {
	ID  int64  `xmlrpc:"id"`
	NVR string `xmlrpc:"nvr"`
}

type RPMInfo struct {
	BuildID          int         `xmlrpc:"build_id"`
	Name             string      `xmlrpc:"name"`
	Extra            interface{} `xmlrpc:"extra"`
	ExternalRepoID   int         `xmlrpc:"external_repo_id"`
	Buildtime        int         `xmlrpc:"buildtime"`
	ID               int         `xmlrpc:"id"`
	Epoch            int         `xmlrpc:"epoch"`
	Version          string      `xmlrpc:"version"`
	BuildrootID      int         `xmlrpc:"buildroot_id"`
	MetadataOnly     bool        `xmlrpc:"metadata_only"`
	Release          string      `xmlrpc:"release"`
	Arch             string      `xmlrpc:"arch"`
	Payloadhash      string      `xmlrpc:"payloadhash"`
	ExternalRepoName string      `xmlrpc:"external_repo_name"`
	Size             int         `xmlrpc:"size"`
}
