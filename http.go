package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "),
	[]byte("DELETE "), []byte("HEAD "), []byte("PATCH "),
	[]byte("OPTIONS "), []byte("CONNECT "), []byte("TRACE "),
}

var httpResponsePrefixes = [][]byte{
	[]byte("HTTP/1.0 "), []byte("HTTP/1.1 "), []byte("HTTP/2"),
}

type ParsedHTTP struct {
	IsHTTP     bool
	IsRequest  bool
	Method     string
	URL        string
	Protocol   string
	StatusCode int
	StatusText string
	Headers    [][2]string // key-value pairs preserving order
	Body       []byte
	RawData    []byte
}

func (p *ParsedHTTP) Header(key string) string {
	lower := strings.ToLower(key)
	for _, h := range p.Headers {
		if strings.ToLower(h[0]) == lower {
			return h[1]
		}
	}
	return ""
}

func (p *ParsedHTTP) ContentType() string {
	ct := p.Header("Content-Type")
	if i := strings.Index(ct, ";"); i >= 0 {
		return strings.TrimSpace(ct[:i])
	}
	return ct
}

func (p *ParsedHTTP) MIMEType() string {
	ct := p.ContentType()
	if ct == "" {
		return ""
	}
	// Simplify for display
	ct = strings.TrimPrefix(ct, "application/")
	ct = strings.TrimPrefix(ct, "text/")
	return ct
}

func ParseHTTPRequest(data []byte) *ParsedHTTP {
	p := &ParsedHTTP{RawData: data}

	for _, m := range httpMethods {
		if bytes.HasPrefix(data, m) {
			p.IsHTTP = true
			p.IsRequest = true
			break
		}
	}
	if !p.IsHTTP {
		return p
	}

	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		// Incomplete, parse what we have
		headerEnd = len(data)
	}

	headerSection := string(data[:headerEnd])
	lines := strings.Split(headerSection, "\r\n")

	// Parse request line
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) >= 2 {
		p.Method = parts[0]
		p.URL = parts[1]
	}
	if len(parts) >= 3 {
		p.Protocol = parts[2]
	}

	// Parse headers
	for _, line := range lines[1:] {
		if i := strings.Index(line, ":"); i >= 0 {
			p.Headers = append(p.Headers, [2]string{
				strings.TrimSpace(line[:i]),
				strings.TrimSpace(line[i+1:]),
			})
		}
	}

	// Body
	if headerEnd+4 <= len(data) {
		p.Body = data[headerEnd+4:]
	}

	return p
}

func ParseHTTPResponse(data []byte) *ParsedHTTP {
	p := &ParsedHTTP{RawData: data}

	for _, prefix := range httpResponsePrefixes {
		if bytes.HasPrefix(data, prefix) {
			p.IsHTTP = true
			p.IsRequest = false
			break
		}
	}
	if !p.IsHTTP {
		return p
	}

	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		headerEnd = len(data)
	}

	headerSection := string(data[:headerEnd])
	lines := strings.Split(headerSection, "\r\n")

	// Parse status line: HTTP/1.1 200 OK
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) >= 1 {
		p.Protocol = parts[0]
	}
	if len(parts) >= 2 {
		p.StatusCode, _ = strconv.Atoi(parts[1])
	}
	if len(parts) >= 3 {
		p.StatusText = parts[2]
	}

	for _, line := range lines[1:] {
		if i := strings.Index(line, ":"); i >= 0 {
			p.Headers = append(p.Headers, [2]string{
				strings.TrimSpace(line[:i]),
				strings.TrimSpace(line[i+1:]),
			})
		}
	}

	if headerEnd+4 <= len(data) {
		p.Body = data[headerEnd+4:]
	}

	return p
}

func isHTTP(data []byte) bool {
	for _, m := range httpMethods {
		if bytes.HasPrefix(data, m) {
			return true
		}
	}
	for _, p := range httpResponsePrefixes {
		if bytes.HasPrefix(data, p) {
			return true
		}
	}
	return false
}

func isTextContentType(ct string) bool {
	lower := strings.ToLower(ct)
	return strings.HasPrefix(lower, "text/") ||
		strings.Contains(lower, "json") ||
		strings.Contains(lower, "xml") ||
		strings.Contains(lower, "javascript") ||
		strings.Contains(lower, "x-www-form-urlencoded") ||
		strings.Contains(lower, "html")
}

func isPrintableText(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	if !utf8.Valid(data) {
		return false
	}
	nonPrintable := 0
	total := 0
	for _, r := range string(data) {
		total++
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			nonPrintable++
		}
	}
	return float64(nonPrintable)/float64(total) < 0.05
}

const maxTextDisplay = 16 * 1024

// formatRaw renders the entire payload as readable text or hex fallback
func formatRaw(data []byte) string {
	if len(data) == 0 {
		return "(no data)"
	}
	if isPrintableText(data) {
		if len(data) > maxTextDisplay {
			return string(data[:maxTextDisplay]) + fmt.Sprintf("\n... (%d more bytes)", len(data)-maxTextDisplay)
		}
		return string(data)
	}
	return hex.Dump(data)
}

// formatHeaders renders only the HTTP headers section
func formatHeaders(parsed *ParsedHTTP) string {
	if !parsed.IsHTTP {
		return "(not HTTP)"
	}
	var buf bytes.Buffer
	if parsed.IsRequest {
		fmt.Fprintf(&buf, "%s %s %s\n\n", parsed.Method, parsed.URL, parsed.Protocol)
	} else {
		fmt.Fprintf(&buf, "%s %d %s\n\n", parsed.Protocol, parsed.StatusCode, parsed.StatusText)
	}
	for _, h := range parsed.Headers {
		fmt.Fprintf(&buf, "%s: %s\n", h[0], h[1])
	}
	return buf.String()
}

// formatHex renders the data as a hex dump
func formatHex(data []byte) string {
	if len(data) == 0 {
		return "(no data)"
	}
	if len(data) > maxTextDisplay {
		return hex.Dump(data[:maxTextDisplay]) + fmt.Sprintf("\n... (%d more bytes)", len(data)-maxTextDisplay)
	}
	return hex.Dump(data)
}
