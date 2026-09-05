package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Backend filtering is intentionally small.
// EdgeGuard owns bot/scanner classification, ASN checks, behavior profiling,
// campaign-entry enforcement, Turnstile, and edge block decisions.
// PRISM only verifies the trusted EdgeGuard handoff and keeps a last-resort
// origin rate limit so duplicated/stale filtering rules cannot disagree with
// the edge decision.

// Optional backend allowlist. Leave empty to allow all EdgeGuard-approved IPs.
// Entries may be exact IPs or CIDR ranges.
var allowedIPs []string

const (
	// This is deliberately much looser than EdgeGuard's behavioral limits.
	// It exists only as an emergency origin safeguard and should not become a
	// second traffic-classification system.
	maxRequestsPerIP = 600
	rateWindow       = time.Minute
)

type ipWindow struct {
	count       int
	windowStart time.Time
}

type rateLimiter struct {
	mu       sync.Mutex
	requests map[string]*ipWindow
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{requests: make(map[string]*ipWindow)}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	window, ok := rl.requests[ip]
	if !ok || now.Sub(window.windowStart) >= rateWindow {
		rl.requests[ip] = &ipWindow{count: 1, windowStart: now}
		return true
	}

	window.count++
	return window.count <= maxRequestsPerIP
}

func (rl *rateLimiter) count(ip string) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if window, ok := rl.requests[ip]; ok {
		return window.count
	}
	return 0
}

func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for now := range ticker.C {
		rl.mu.Lock()
		for ip, window := range rl.requests {
			if now.Sub(window.windowStart) >= rateWindow {
				delete(rl.requests, ip)
			}
		}
		rl.mu.Unlock()
	}
}

var limiter = newRateLimiter()

// isBlocked is the PRISM origin's final lightweight gate.
// validateEdgeGuardOrigin() already authenticates the Worker-to-origin request
// before mainHandler runs; this function additionally requires EdgeGuard's
// explicit allow decision and applies only generic backend controls.
func isBlocked(r *http.Request) (bool, string) {
	ip := extractIP(r)

	// The Worker sets this header only when forwarding an allowed request.
	// Incoming client-supplied X-EdgeGuard-* headers are stripped by EdgeGuard
	// before it writes its own trusted values.
	status := strings.ToUpper(strings.TrimSpace(r.Header.Get("X-EdgeGuard-Status")))
	if status != "ALLOWED" {
		return true, "missing or invalid EdgeGuard allow status"
	}

	if len(allowedIPs) > 0 {
		allowed := false
		for _, entry := range allowedIPs {
			if ipMatches(ip, entry) {
				allowed = true
				break
			}
		}
		if !allowed {
			return true, fmt.Sprintf("IP not in backend allowlist: %s", ip)
		}
	}

	if !limiter.allow(ip) {
		return true, fmt.Sprintf(
			"origin rate limit exceeded: %s (%d req/min)",
			ip,
			limiter.count(ip),
		)
	}

	return false, ""
}

// ipMatches reports whether ip equals pattern or belongs to a CIDR range.
func ipMatches(ip, pattern string) bool {
	ip = strings.TrimSpace(ip)
	pattern = strings.TrimSpace(pattern)
	if ip == "" || pattern == "" {
		return false
	}

	if strings.Contains(pattern, "/") {
		_, network, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		parsed := net.ParseIP(ip)
		return parsed != nil && network.Contains(parsed)
	}

	return ip == pattern
}

// blockResponse intentionally reveals no internal filtering details.
func blockResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("Not Found"))
}
