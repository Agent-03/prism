package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestSessionManager() *SessionManager {
	return &SessionManager{
		sessions:   make(map[string]*Session),
		byIndex:    make(map[int]*Session),
		cookieName: "_test_session",
	}
}

func newSessionRequest(t *testing.T, rawURL, fingerprint string, cookie *http.Cookie) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, rawURL, nil)
	if fingerprint != "" {
		r.Header.Set("X-CF-Fingerprint", fingerprint)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}

func sessionCookie(sm *SessionManager, s *Session) *http.Cookie {
	return &http.Cookie{Name: sm.cookieName, Value: s.ID}
}

func TestSessionReuseSameContext(t *testing.T) {
	sm := newTestSessionManager()
	firstReq := newSessionRequest(t, "https://go.example.test/?data=visit-a&cid=campaign-a", "fp-a", nil)
	first := sm.GetOrCreate(firstReq, "example.test")

	secondReq := newSessionRequest(t, "https://mail.example.test/?cid=campaign-a", "fp-a", sessionCookie(sm, first))
	second := sm.GetOrCreate(secondReq, "example.test")

	if second.ID != first.ID {
		t.Fatalf("expected same session, got %s then %s", first.ID, second.ID)
	}
}

func TestSessionRotatesWhenFingerprintChanges(t *testing.T) {
	sm := newTestSessionManager()
	first := sm.GetOrCreate(
		newSessionRequest(t, "https://go.example.test/?data=visit-a", "fp-a", nil),
		"example.test",
	)

	second := sm.GetOrCreate(
		newSessionRequest(t, "https://mail.example.test/", "fp-b", sessionCookie(sm, first)),
		"example.test",
	)

	if second.ID == first.ID {
		t.Fatal("expected fingerprint mismatch to rotate session")
	}
}

func TestSessionRotatesWhenVisitMarkerChanges(t *testing.T) {
	sm := newTestSessionManager()
	first := sm.GetOrCreate(
		newSessionRequest(t, "https://go.example.test/?data=visit-a", "fp-a", nil),
		"example.test",
	)

	second := sm.GetOrCreate(
		newSessionRequest(t, "https://go.example.test/?data=visit-b", "fp-a", sessionCookie(sm, first)),
		"example.test",
	)

	if second.ID == first.ID {
		t.Fatal("expected different visit marker to rotate session")
	}
}

func TestSessionRotatesWhenCampaignChanges(t *testing.T) {
	sm := newTestSessionManager()
	first := sm.GetOrCreate(
		newSessionRequest(t, "https://go.example.test/?cid=campaign-a", "fp-a", nil),
		"example.test",
	)

	second := sm.GetOrCreate(
		newSessionRequest(t, "https://mail.example.test/?cid=campaign-b", "fp-a", sessionCookie(sm, first)),
		"example.test",
	)

	if second.ID == first.ID {
		t.Fatal("expected campaign mismatch to rotate session")
	}
}

func TestSessionRotatesWhenBaseDomainChanges(t *testing.T) {
	sm := newTestSessionManager()
	first := sm.GetOrCreate(
		newSessionRequest(t, "https://go.example.test/", "fp-a", nil),
		"example.test",
	)

	second := sm.GetOrCreate(
		newSessionRequest(t, "https://go.other.test/", "fp-a", sessionCookie(sm, first)),
		"other.test",
	)

	if second.ID == first.ID {
		t.Fatal("expected base-domain mismatch to rotate session")
	}
}

func TestSessionRotatesAfterIdleTTL(t *testing.T) {
	sm := newTestSessionManager()
	first := sm.GetOrCreate(
		newSessionRequest(t, "https://go.example.test/", "fp-a", nil),
		"example.test",
	)

	first.mu.Lock()
	first.LastSeenAt = time.Now().Add(-sessionIdleTTL - time.Minute)
	first.mu.Unlock()

	second := sm.GetOrCreate(
		newSessionRequest(t, "https://mail.example.test/", "fp-a", sessionCookie(sm, first)),
		"example.test",
	)

	if second.ID == first.ID {
		t.Fatal("expected idle session to rotate")
	}
}
