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
