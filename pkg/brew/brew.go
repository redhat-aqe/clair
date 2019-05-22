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

import (
	"strconv"
	"time"

	"github.com/kolo/xmlrpc"
	cache "github.com/patrickmn/go-cache"
)

var c = cache.New(24*time.Hour, 30*time.Minute)

// Brew client API structure
type Brew struct {
	URL    string
	Client *xmlrpc.Client
}

// NewClient - create new Brew client for giver URL
func NewClient(url string) (brew Brew) {
	client, err := xmlrpc.NewClient(url, nil)
	if err != nil {
		panic("Unable to create Brew client")
	}
	return Brew{
		url,
		client,
	}
}

// GetBuildInfo - returns metadata of given build object
func (brew *Brew) GetBuildInfo(nvr int) (result BuildInfo) {
	value, found := c.Get(strconv.Itoa(nvr))
	if !found {
		err := brew.request("getBuild", nvr, &result)
		if err != nil {
			panic(err)
		}
		c.Set(strconv.Itoa(nvr), result, cache.DefaultExpiration)
		return result
	}
	return value.(BuildInfo)
}

// GetRPMInfo - returns metadata of given rpm object
func (brew *Brew) GetRPMInfo(nvra string) (result RPMInfo) {
	err := brew.request("getRPM", nvra, &result)
	if err != nil {
		panic(err)
	}
	return
}

func (brew *Brew) request(serviceMethod string, args interface{}, reply interface{}) interface{} {
	var err interface{}
	for i := 0; i < 3; i++ {
		err = brew.Client.Call(serviceMethod, args, reply)
		if err == nil {
			return nil
		}
		// sleep and re-try
		time.Sleep(100 * time.Millisecond)

	}
	panic(err)
}
