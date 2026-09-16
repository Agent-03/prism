package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

// browserTransport returns an http.Transport whose outbound TLS handshake
// mimics Chrome (JA3 fingerprint) and speaks HTTP/1.1 only — so the upstream
// (Yahoo, etc.) sees a browser-like client instead of Go's recognizable stack.
var browserHTTPTransport = newBrowserTransport()

func newBrowserTransport() *http.Transport {
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
			rawConn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}

			// Start from Chrome's real ClientHello, then force ALPN to HTTP/1.1
			// so we don't expose Go's HTTP/2 fingerprint.
			spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
			if err != nil {
				rawConn.Close()
				return nil, err
			}
			for i, ext := range spec.Extensions {
				if _, ok := ext.(*utls.ALPNExtension); ok {
					spec.Extensions[i] = &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}}
				}
			}

			cfg := &utls.Config{ServerName: host, InsecureSkipVerify: true}
			uconn := utls.UClient(rawConn, cfg, utls.HelloCustom)

			if err := uconn.ApplyPreset(&spec); err != nil {
				rawConn.Close()
				return nil, err
			}
			if err := uconn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				return nil, err
			}
			return uconn, nil
		},
		// Disable HTTP/2 entirely (empty non-nil map) → plain HTTP/1.1.
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
}
