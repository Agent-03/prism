package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// handleGetConfig exposes the current read-only DB-backed runtime state for the
// requested domain. Runtime configuration is authoritative; there is no local
// target-toggle or webhook-mutation layer anymore.
func handleGetConfig(w http.ResponseWriter, r *http.Request) {
	_, baseDomain, _ := resolveHost(r.Host)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	runtimeState, runtimeOK := getRuntimeDomainConfig(baseDomain)
	if !runtimeOK {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"configured": false,
			"hostname":   baseDomain,
		})
		return
	}

	landingMode := strings.ToLower(strings.TrimSpace(runtimeState.Landing.Mode))
	landingTemplate := ""
	if landingMode == "template" {
		landingTemplate = strings.TrimSpace(runtimeState.Landing.SelectedTemplateID)
		if landingTemplate == "" {
			landingTemplate = strings.TrimSpace(runtimeState.Landing.TemplateID)
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"configured":       true,
		"domain_id":        runtimeState.DomainID,
		"hostname":         runtimeState.Hostname,
		"enabled":          runtimeState.Enabled,
		"routing_version":  runtimeState.RoutingVersion,
		"landing_enabled":  runtimeState.Landing.Enabled,
		"landing_mode":     landingMode,
		"landing_template": landingTemplate,
		"landing_revision": runtimeState.Landing.Revision,
		"content_mode":     runtimeState.Content.Mode,
		"content_profile":  runtimeState.Content.ProfileID,
		"content_fallback": runtimeState.Content.Fallback,
		"content_version":  runtimeState.Content.Version,
	})
}
