package engine

import (
	"encoding/base64"
	"math"
	"net/url"
)

// Limits for the decoding stage. Decoded text is never larger than the
// blob, so the limits apply only to blobs above the default size limit.
const (
	minBase64Run       = 40
	minURLEncodedRun   = 16
	maxDecodedPerBlob  = 16 << 20
	maxSegmentsPerBlob = 1 << 20
)

// segment is decoded text plus the offset of the encoded text in the blob.
type segment struct {
	offset int
	data   []byte
	kind   string
}

// entropy returns the Shannon entropy of data in bits per byte.
func entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func isBase64Byte(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' ||
		b == '+' || b == '/' || b == '-' || b == '_'
}

func isHexByte(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}

// mostlyText reports whether at least 90% of the bytes are printable ASCII
// or whitespace. Random bytes from a false base64 decode fail this test.
func mostlyText(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	good := 0
	for _, b := range data {
		if b >= 0x20 && b < 0x7f || b == '\n' || b == '\r' || b == '\t' {
			good++
		}
	}
	return good*10 >= len(data)*9
}

// decodeSegments finds base64 runs of 40 or more characters and
// URL-encoded strings, and decodes them. It decodes one level only.
func decodeSegments(data []byte) []segment {
	var segs []segment
	total := 0
	add := func(s segment) bool {
		if len(segs) >= maxSegmentsPerBlob || total+len(s.data) > maxDecodedPerBlob {
			return false
		}
		segs = append(segs, s)
		total += len(s.data)
		return true
	}

	for i := 0; i < len(data); {
		if !isBase64Byte(data[i]) {
			i++
			continue
		}
		start := i
		allHex := true
		hasStd, hasURL := false, false
		for i < len(data) && isBase64Byte(data[i]) {
			switch data[i] {
			case '+', '/':
				hasStd = true
			case '-', '_':
				hasURL = true
			}
			if !isHexByte(data[i]) {
				allHex = false
			}
			i++
		}
		end := i
		for i < len(data) && data[i] == '=' && i-end < 2 {
			i++
		}
		run := data[start:end]
		// Hex runs are hashes and commit IDs. A run with both alphabets is
		// not base64.
		if len(run) < minBase64Run || allHex || hasStd && hasURL {
			continue
		}
		if len(run)%4 == 1 {
			run = run[:len(run)-1]
		}
		enc := base64.RawStdEncoding
		if hasURL {
			enc = base64.RawURLEncoding
		}
		out := make([]byte, enc.DecodedLen(len(run)))
		n, err := enc.Decode(out, run)
		if err != nil || n < 16 || !mostlyText(out[:n]) {
			continue
		}
		if !add(segment{offset: start, data: out[:n], kind: "base64"}) {
			return segs
		}
	}

	for i := 0; i+2 < len(data); i++ {
		if data[i] != '%' || !isHexByte(data[i+1]) || !isHexByte(data[i+2]) {
			continue
		}
		start, end := i, i
		for start > 0 && !isTokenBreak(data[start-1]) {
			start--
		}
		for end < len(data) && !isTokenBreak(data[end]) {
			end++
		}
		i = end
		if end-start < minURLEncodedRun {
			continue
		}
		decoded, err := url.QueryUnescape(string(data[start:end]))
		if err != nil || decoded == string(data[start:end]) {
			continue
		}
		if !add(segment{offset: start, data: []byte(decoded), kind: "url"}) {
			return segs
		}
	}
	return segs
}

func isTokenBreak(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '"', '\'', '`', '<', '>', '(', ')', '[', ']', '{', '}', ',', ';':
		return true
	}
	return false
}
