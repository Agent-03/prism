package main

import (
	"bufio"
	"io"
	"log"
	"os"
	"strings"
)

// consoleLogWriter keeps production console output intentionally small.
// Existing application logging calls remain untouched; this writer only
// controls what reaches stdout/PM2.
type consoleLogWriter struct {
	dst io.Writer
}

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

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Session creation is useful operational context, but the original line
		// contains the full UA/IP and is too noisy. Collapse it to one clean line.
		if strings.Contains(line, "New session:") {
			index := fieldBetween(line, "[+] [", "] New session:")
			rest := fieldAfter(line, "New session:")
			id := ""
			if fields := strings.Fields(rest); len(fields) > 0 {
				id = fields[0]
			}

			out := "🟢 SESSION  •  New visitor"
			if index != "" {
				out += "  •  #" + index
			}
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
	// Convert the existing verbose root-request debug message into the one
	// page-navigation event we actually want to see.
	if strings.Contains(line, "Request reached Go!") {
		host := fieldBetween(line, "Host: ", " | Path:")
		path := fieldBetween(line, "Path: ", " | Method:")
		method := strings.TrimSpace(fieldAfter(line, "Method: "))

		if method == "GET" && (path == "/" || path == "/index.html") {
			prefix := ""
			if i := strings.Index(line, "["); i > 0 {
				prefix = strings.TrimSpace(line[:i]) + " "
			}
			return prefix + "🌐 PAGE     •  Landed  •  " + host + path, true
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
