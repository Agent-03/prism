package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"
	"strings"

	"github.com/dsnet/compress/brotli"
)

// ══════════════════════════════════════════════════════════
//  DECOMPRESS — handles gzip, deflate, brotli, or none
// ══════════════════════════════════════════════════════════

func decompress(resp *http.Response) ([]byte, error) {
	body := resp.Body
	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))

	switch encoding {
	case "gzip", "x-gzip":
		reader, err := gzip.NewReader(body)
		if err != nil {
			body.Close()
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(reader)

	case "deflate":
		reader := flate.NewReader(body)
		defer reader.Close()
		return io.ReadAll(reader)

	case "br":
		reader, err := brotli.NewReader(body, &brotli.ReaderConfig{})
		if err != nil {
			body.Close()
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(reader)

	default:
		defer body.Close()
		return io.ReadAll(body)
	}
}

// ══════════════════════════════════════════════════════════
//  COMPRESS — kept for reference, no longer called
//  (we always send uncompressed now)
// ══════════════════════════════════════════════════════════

func gzipCompress(input []byte) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(input)
	w.Flush()
	w.Close()
	return b.Bytes()
}

func deflateCompress(input []byte) []byte {
	var b bytes.Buffer
	w, _ := flate.NewWriter(&b, 0)
	w.Write(input)
	w.Flush()
	w.Close()
	return b.Bytes()
}
