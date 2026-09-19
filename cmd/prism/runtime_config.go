package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type runtimeLandingConfig struct {
	Enabled            bool   `json:"enabled"`
	Mode               string `json:"mode"`
	TemplateID         string `json:"templateId"`
	SelectedTemplateID string `json:"selectedTemplateId"`
	Revision           int64  `json:"revision"`
}

type runtimeContentConfig struct {
	Mode      string `json:"mode"`
	ProfileID string `json:"profileId"`
	Fallback  string `json:"fallback"`
	Version   int64  `json:"version"`
}

type runtimeDomainConfig struct {
	DomainID       string               `json:"domainId"`
	Hostname       string               `json:"hostname"`
	Enabled        bool                 `json:"enabled"`
	RoutingVersion int64                `json:"routingVersion"`
	Landing        runtimeLandingConfig `json:"landing"`
	Content        runtimeContentConfig `json:"content"`
}

type runtimeConfigSnapshot struct {
	Version string                `json:"version"`
	Domains []runtimeDomainConfig `json:"domains"`
}

var (
	runtimeConfigMu      sync.RWMutex
	runtimeConfigVersion string
	runtimeConfigETag    string
	runtimeConfigDomains = map[string]runtimeDomainConfig{}
)

func normalizeRuntimeHostname(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func runtimeConfigRefreshInterval() time.Duration {
	value := strings.TrimSpace(os.Getenv("PRISM_RUNTIME_CONFIG_REFRESH_SECONDS"))
	if value == "" {
		return 30 * time.Second
	}

	seconds, err := strconv.Atoi(value)
	if err != nil || seconds < 5 {
		return 30 * time.Second
	}
	return time.Duration(seconds) * time.Second
}

func landingTemplateFromRuntime(remote runtimeDomainConfig) string {
	switch strings.ToLower(strings.TrimSpace(remote.Landing.Mode)) {
	case "direct":
		return "none"
	case "template":
		if templateID := strings.TrimSpace(remote.Landing.SelectedTemplateID); templateID != "" {
			return templateID
		}
		return strings.TrimSpace(remote.Landing.TemplateID)
	default:
		return ""
	}
}

func fetchRuntimeConfig(client *http.Client, endpoint, secret string) (bool, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-NSL-Prism-Config-Secret", secret)

	runtimeConfigMu.RLock()
	etag := runtimeConfigETag
	runtimeConfigMu.RUnlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("runtime config endpoint returned HTTP %d", resp.StatusCode)
	}

	var snapshot runtimeConfigSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&snapshot); err != nil {
		return false, fmt.Errorf("decode runtime config: %w", err)
	}

	next := make(map[string]runtimeDomainConfig, len(snapshot.Domains))
	for _, domain := range snapshot.Domains {
		hostname := normalizeRuntimeHostname(domain.Hostname)
		if hostname == "" {
			continue
		}
		domain.Hostname = hostname
		next[hostname] = domain
	}

	runtimeConfigMu.Lock()
	runtimeConfigDomains = next
	runtimeConfigVersion = snapshot.Version
	runtimeConfigETag = resp.Header.Get("ETag")
	runtimeConfigMu.Unlock()

	return true, nil
}

func refreshRuntimeConfig() error {
	endpoint := strings.TrimSpace(os.Getenv("PRISM_RUNTIME_CONFIG_URL"))
	secret := strings.TrimSpace(os.Getenv("PRISM_RUNTIME_CONFIG_SECRET"))
	if endpoint == "" || secret == "" {
		return errors.New("PRISM_RUNTIME_CONFIG_URL and PRISM_RUNTIME_CONFIG_SECRET are required")
	}

	client := &http.Client{Timeout: 8 * time.Second}
	changed, err := fetchRuntimeConfig(client, endpoint, secret)
	if err != nil {
		return err
	}
	if changed {
		runtimeConfigMu.RLock()
		count := len(runtimeConfigDomains)
		version := runtimeConfigVersion
		runtimeConfigMu.RUnlock()
		log.Printf("[config] Runtime configuration refreshed: %d domains, version %s", count, version)
	}
	return nil
}

func initRuntimeConfigReader() error {
	if strings.TrimSpace(os.Getenv("PRISM_RUNTIME_CONFIG_URL")) == "" ||
		strings.TrimSpace(os.Getenv("PRISM_RUNTIME_CONFIG_SECRET")) == "" {
		return errors.New("PRISM_RUNTIME_CONFIG_URL and PRISM_RUNTIME_CONFIG_SECRET are required")
	}

	// Runtime config is authoritative, so require the first DB-backed snapshot
	// before the HTTP server starts accepting requests.
	if err := refreshRuntimeConfig(); err != nil {
		return fmt.Errorf("initial runtime configuration refresh failed: %w", err)
	}

	interval := runtimeConfigRefreshInterval()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if err := refreshRuntimeConfig(); err != nil {
				log.Printf("[config] Runtime configuration refresh failed: %v", err)
			}
		}
	}()

	return nil
}

func getRuntimeDomainConfig(hostname string) (runtimeDomainConfig, bool) {
	runtimeConfigMu.RLock()
	defer runtimeConfigMu.RUnlock()
	config, ok := runtimeConfigDomains[normalizeRuntimeHostname(hostname)]
	return config, ok
}
