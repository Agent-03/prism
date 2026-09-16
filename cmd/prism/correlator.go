package main

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ══════════════════════════════════════════════════════════
//
//	OBSERVATION EVENT
//
// ══════════════════════════════════════════════════════════
type ObservationEvent struct {
	Timestamp   time.Time
	SessionID   string
	IP          string
	IPPrefix    string
	Fingerprint string
	UserAgent   string
	Route       string
	Action      string // "allowed" or "blocked"
}

// ══════════════════════════════════════════════════════════
//
//	DYNAMIC SWARM BLOCKING STRUCTS
//
// ══════════════════════════════════════════════════════════
type AttemptCounter struct {
	Count     int
	FirstSeen time.Time
	mu        sync.Mutex
}

type BanRecord struct {
	ExpiresAt time.Time
	Reason    string
}

const (
	BlockThreshold = 15               // Auto-ban after 15 blocked attempts
	BlockWindow    = 60 * time.Second // Within this time window
	BanDuration    = 1 * time.Hour    // How long the dynamic ban lasts
)

// ══════════════════════════════════════════════════════════
//
//	CORRELATION ENGINE
//
// ══════════════════════════════════════════════════════════
type CorrelationEngine struct {
	events chan ObservationEvent
	wg     sync.WaitGroup

	// Sharded maps for session correlation (Phase 2 foundation)
	featureShards [16]sync.Map
	sessionShards [16]sync.Map

	// Dynamic Swarm Blocking (Path B)
	blockAttempts sync.Map // key: "prefix:fingerprint", value: *AttemptCounter
	dynamicBans   sync.Map // key: "prefix" or "FP:fingerprint", value: BanRecord
}

var correlator *CorrelationEngine

func initCorrelator() {
	correlator = &CorrelationEngine{
		events: make(chan ObservationEvent, 10000),
	}

	correlator.wg.Add(1)
	go correlator.run()

	// Start the garbage collector for old bans and attempts
	correlator.wg.Add(1)
	go correlator.cleanup()

	log.Printf("[*] Advanced correlation engine started (Dynamic Swarm Blocking enabled)")
}

func (c *CorrelationEngine) Emit(evt ObservationEvent) {
	select {
	case c.events <- evt:
	default:
		// Drop event if channel is full to protect HTTP handler latency (O(1) non-blocking)
	}
}

func (c *CorrelationEngine) run() {
	defer c.wg.Done()
	for evt := range c.events {
		c.processEvent(evt)
	}
}

func (c *CorrelationEngine) processEvent(evt ObservationEvent) {
	// PATH B: Handle Blocked Traffic for Swarm Detection
	if evt.Action == "blocked" && evt.Fingerprint != "" && evt.IPPrefix != "" {
		key := evt.IPPrefix + ":" + evt.Fingerprint

		// 1. Check if this prefix is already dynamically banned
		if ban, ok := c.dynamicBans.Load(evt.IPPrefix); ok {
			if ban.(BanRecord).ExpiresAt.After(time.Now()) {
				return // Already banned, do nothing
			}
		}

		// 2. Increment block attempt counter
		val, _ := c.blockAttempts.LoadOrStore(key, &AttemptCounter{FirstSeen: evt.Timestamp})
		counter := val.(*AttemptCounter)

		counter.mu.Lock()
		// Reset if window expired
		if time.Since(counter.FirstSeen) > BlockWindow {
			counter.Count = 1
			counter.FirstSeen = evt.Timestamp
		} else {
			counter.Count++
		}

		currentCount := counter.Count
		counter.mu.Unlock()

		// 3. Escalate to Dynamic Ban if threshold crossed
		if currentCount >= BlockThreshold {
			reason := fmt.Sprintf("swarm block: %d attempts in %v", currentCount, BlockWindow)

			// Ban the IP Prefix
			c.dynamicBans.Store(evt.IPPrefix, BanRecord{
				ExpiresAt: time.Now().Add(BanDuration),
				Reason:    reason,
			})

			// ALSO ban the specific fingerprint to catch distributed swarms using the same tool
			c.dynamicBans.Store("FP:"+evt.Fingerprint, BanRecord{
				ExpiresAt: time.Now().Add(BanDuration),
				Reason:    reason,
			})

			log.Printf("[🔥] DYNAMIC SWARM BAN: Prefix %s & Fingerprint banned for %v",
				evt.IPPrefix, BanDuration)
		}
	}
}

// IsDynamicallyBlocked checks if an IP prefix or fingerprint is currently under a dynamic ban.
func (c *CorrelationEngine) IsDynamicallyBlocked(ipPrefix, fingerprint string) (bool, string) {
	now := time.Now()

	// Check IP Prefix ban
	if ban, ok := c.dynamicBans.Load(ipPrefix); ok {
		record := ban.(BanRecord)
		if record.ExpiresAt.After(now) {
			return true, fmt.Sprintf("dynamic swarm ban (prefix): %s", record.Reason)
		}
	}

	// Check Fingerprint ban (if a specific TLS stack is hammering us from multiple IPs)
	if fingerprint != "" {
		if ban, ok := c.dynamicBans.Load("FP:" + fingerprint); ok {
			record := ban.(BanRecord)
			if record.ExpiresAt.After(now) {
				return true, fmt.Sprintf("dynamic swarm ban (fingerprint): %s", record.Reason)
			}
		}
	}

	return false, ""
}

func (c *CorrelationEngine) cleanup() {
	defer c.wg.Done()
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		now := time.Now()

		// Clean expired bans
		c.dynamicBans.Range(func(key, value interface{}) bool {
			if value.(BanRecord).ExpiresAt.Before(now) {
				c.dynamicBans.Delete(key)
			}
			return true
		})

		// Clean old attempt counters
		c.blockAttempts.Range(func(key, value interface{}) bool {
			if now.Sub(value.(*AttemptCounter).FirstSeen) > BlockWindow {
				c.blockAttempts.Delete(key)
			}
			return true
		})
	}
}

func (c *CorrelationEngine) Shutdown() {
	close(c.events)
	c.wg.Wait()
	log.Printf("[*] Correlation engine shut down.")
}
