package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/tailscale/hujson"
)

// configFile represents the on-disk configuration for this tsproxy instance.
type config struct {
	// StateDir is where app state is stored, this should be persisted between
	// rounds. Defaults to the user cache dir. If the Kubernetes config is set,
	// it overrides this.
	StateDir string `json:"stateDir"`
	// MetricsDiscovery port sets the port we should listen for internal items
	// for, i.e metrics and discovery info
	MetricsDiscoveryPort int `json:"port"`
	// LogTailscale indicates that we should log tailscale output
	LogTailscale bool       `json:"logTailscale"`
	Upstreams    []upstream `json:"upstreams"`
}

// ConfigUpstream represents the configuration for a single upstream for this
// tsproxy instance.
type upstream struct {
	Name string `json:"name"`
	// Backend is the URL to the backend that serves this upstream
	Backend    string `json:"backend"`
	Prometheus bool   `json:"prometheus"`
	Funnel     bool   `json:"funnel"`

	backendURL *url.URL
}

func parseAndValidateConfig(cfg []byte) (config, error) {
	b := []byte(os.Expand(string(cfg), getenvWithDefault))
	var c config
	b, err := hujson.Standardize(b)
	if err != nil {
		return c, fmt.Errorf("standardizing config: %w", err)
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("unmarshaling config: %w", err)
	}

	// defaults
	if c.MetricsDiscoveryPort == 0 {
		c.MetricsDiscoveryPort = 32019
	}

	// validation
	var verr error
	if len(c.Upstreams) == 0 {
		verr = errors.Join(verr, errors.New("at least one upstream must be provided"))
	}
	for _, u := range c.Upstreams {
		if u.Name == "" {
			verr = errors.Join(verr, errors.New("upstreams must have a name"))
		}
		if u.Backend == "" {
			verr = errors.Join(verr, fmt.Errorf("upstream %s must have a backend", u.Name))
		} else {
			p, err := url.Parse(u.Backend)
			if err != nil {
				verr = errors.Join(verr, fmt.Errorf("upstream %s backend url %s failed parsing: %w", u.Name, u.Backend, err))
			} else {
				u.backendURL = p
			}
		}
	}

	return c, nil
}

// getenvWithDefault maps FOO:-default to $FOO or default if $FOO is unset or
// null.
func getenvWithDefault(key string) string {
	parts := strings.SplitN(key, ":-", 2)
	val := os.Getenv(parts[0])
	if val == "" && len(parts) == 2 {
		val = parts[1]
	}
	return val
}
