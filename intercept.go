package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// InterceptResult is sent back from the UI to the proxy goroutine.
type InterceptResult struct {
	Data    []byte
	Forward bool // false = drop the connection
}

// InterceptRequest is sent from the proxy goroutine to the UI.
type InterceptRequest struct {
	Conn   *Connection
	Data   []byte
	Result chan InterceptResult
}

// FilterField specifies which part of the request to match against.
type FilterField int

const (
	FilterHost FilterField = iota
	FilterURL
	FilterMethod
	FilterContentType
	FilterBody
	FilterHeader
	FilterAwk
)

func (f FilterField) String() string {
	switch f {
	case FilterHost:
		return "host"
	case FilterURL:
		return "url"
	case FilterMethod:
		return "method"
	case FilterContentType:
		return "content-type"
	case FilterBody:
		return "body"
	case FilterHeader:
		return "header"
	case FilterAwk:
		return "awk"
	}
	return "unknown"
}

// InterceptFilter is a single match rule — either regex-based or awk-based.
type InterceptFilter struct {
	Field   FilterField
	Pattern *regexp.Regexp // nil for awk filters
	AwkExpr string        // non-empty for awk filters
	Raw     string        // original pattern/expression string for display
}

func (f *InterceptFilter) String() string {
	if f.Field == FilterAwk {
		return fmt.Sprintf("awk { %s }", f.Raw)
	}
	return fmt.Sprintf("%s =~ /%s/", f.Field, f.Raw)
}

// MatchRegex tests the filter against a string value (for non-awk filters).
func (f *InterceptFilter) MatchRegex(value string) bool {
	if f.Pattern == nil {
		return false
	}
	return f.Pattern.MatchString(value)
}

// MatchAwk runs the awk expression against the request data.
// Available awk variables: method, url, host, content_type, body_len, status, proto.
// $0 is the full raw request. Each line of the request is a record.
// If awk produces any output, the filter matches.
func (f *InterceptFilter) MatchAwk(conn *Connection, data []byte, parsed *ParsedHTTP) bool {
	if f.AwkExpr == "" {
		return false
	}

	// Build awk variables from parsed HTTP
	vars := []string{}
	addVar := func(name, value string) {
		vars = append(vars, "-v", fmt.Sprintf("%s=%s", name, value))
	}

	addVar("host", conn.Target)
	if parsed.IsHTTP {
		addVar("method", parsed.Method)
		addVar("url", parsed.URL)
		addVar("proto", parsed.Protocol)
		addVar("content_type", parsed.Header("Content-Type"))
		addVar("body_len", strconv.Itoa(len(parsed.Body)))

		// All headers as a single newline-delimited string
		var hdrs strings.Builder
		for _, h := range parsed.Headers {
			hdrs.WriteString(h[0])
			hdrs.WriteString(": ")
			hdrs.WriteString(h[1])
			hdrs.WriteString("\n")
		}
		addVar("headers", hdrs.String())
	} else {
		addVar("method", "")
		addVar("url", "")
		addVar("proto", "")
		addVar("content_type", "")
		addVar("body_len", strconv.Itoa(len(data)))
		addVar("headers", "")
	}

	// Build: awk -v method=... -v url=... 'expression' <<< data
	args := append(vars, f.AwkExpr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "awk", args...)
	cmd.Stdin = bytes.NewReader(data)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil

	err := cmd.Run()
	if err != nil {
		// awk exited non-zero or timed out — no match
		return false
	}

	// If awk produced any output, the filter matches
	return stdout.Len() > 0
}

// Interceptor manages the intercept toggle, filters, and pending request queue.
type Interceptor struct {
	mu      sync.Mutex
	enabled bool
	filters []InterceptFilter
	queue   chan *InterceptRequest
}

func NewInterceptor() *Interceptor {
	return &Interceptor{
		queue: make(chan *InterceptRequest, 64),
	}
}

func (it *Interceptor) IsEnabled() bool {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.enabled
}

func (it *Interceptor) Toggle() bool {
	it.mu.Lock()
	defer it.mu.Unlock()
	it.enabled = !it.enabled
	return it.enabled
}

func (it *Interceptor) SetEnabled(enabled bool) {
	it.mu.Lock()
	defer it.mu.Unlock()
	it.enabled = enabled
}

// AddFilter adds a new regex-based intercept filter.
func (it *Interceptor) AddFilter(field FilterField, pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex %q: %w", pattern, err)
	}
	it.mu.Lock()
	defer it.mu.Unlock()
	it.filters = append(it.filters, InterceptFilter{
		Field:   field,
		Pattern: re,
		Raw:     pattern,
	})
	return nil
}

// AddAwkFilter adds an awk-based intercept filter.
func (it *Interceptor) AddAwkFilter(expr string) error {
	// Validate by running awk with empty input
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "awk", expr)
	cmd.Stdin = strings.NewReader("")
	if err := cmd.Run(); err != nil {
		// Check if it's a syntax error vs just no match
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
			return fmt.Errorf("awk syntax error in %q", expr)
		}
		// Exit code 1 is fine (no match on empty input)
	}

	it.mu.Lock()
	defer it.mu.Unlock()
	it.filters = append(it.filters, InterceptFilter{
		Field:   FilterAwk,
		AwkExpr: expr,
		Raw:     expr,
	})
	return nil
}

// RemoveFilter removes the filter at the given index.
func (it *Interceptor) RemoveFilter(index int) {
	it.mu.Lock()
	defer it.mu.Unlock()
	if index >= 0 && index < len(it.filters) {
		it.filters = append(it.filters[:index], it.filters[index+1:]...)
	}
}

// ClearFilters removes all filters.
func (it *Interceptor) ClearFilters() {
	it.mu.Lock()
	defer it.mu.Unlock()
	it.filters = nil
}

// Filters returns a copy of the current filter list.
func (it *Interceptor) Filters() []InterceptFilter {
	it.mu.Lock()
	defer it.mu.Unlock()
	result := make([]InterceptFilter, len(it.filters))
	copy(result, it.filters)
	return result
}

// ShouldIntercept checks whether a request matches the filter rules.
// If no filters are set, all requests are intercepted.
// If filters are set, at least one must match (OR logic).
func (it *Interceptor) ShouldIntercept(conn *Connection, data []byte) bool {
	it.mu.Lock()
	filters := make([]InterceptFilter, len(it.filters))
	copy(filters, it.filters)
	it.mu.Unlock()

	if len(filters) == 0 {
		return true
	}

	parsed := ParseHTTPRequest(data)

	for i := range filters {
		f := &filters[i]

		if f.Field == FilterAwk {
			if f.MatchAwk(conn, data, parsed) {
				return true
			}
			continue
		}

		var value string
		switch f.Field {
		case FilterHost:
			value = conn.Target
		case FilterURL:
			if parsed.IsHTTP {
				value = parsed.URL
			} else {
				value = conn.Target
			}
		case FilterMethod:
			if parsed.IsHTTP {
				value = parsed.Method
			}
		case FilterContentType:
			if parsed.IsHTTP {
				value = parsed.Header("Content-Type")
			}
		case FilterBody:
			if parsed.IsHTTP && len(parsed.Body) > 0 {
				value = string(parsed.Body)
			} else {
				value = string(data)
			}
		case FilterHeader:
			if parsed.IsHTTP {
				var sb strings.Builder
				for _, h := range parsed.Headers {
					sb.WriteString(h[0])
					sb.WriteString(": ")
					sb.WriteString(h[1])
					sb.WriteString("\n")
				}
				value = sb.String()
			}
		}

		if f.MatchRegex(value) {
			return true
		}
	}

	return false
}

// Submit sends a request for interception and blocks until the UI responds.
func (it *Interceptor) Submit(conn *Connection, data []byte) ([]byte, bool) {
	req := &InterceptRequest{
		Conn:   conn,
		Data:   data,
		Result: make(chan InterceptResult, 1),
	}

	it.queue <- req

	result := <-req.Result
	return result.Data, result.Forward
}

// Pending returns the channel to receive intercept requests from.
func (it *Interceptor) Pending() <-chan *InterceptRequest {
	return it.queue
}

// QueueLen returns the number of pending intercept requests.
func (it *Interceptor) QueueLen() int {
	return len(it.queue)
}

// ParseFilterSpec parses a filter specification string.
//
// Regex filters:  field:pattern       e.g. host:example\.com
// Awk filters:    awk:expression      e.g. awk:method == "POST" && url ~ /login/
//
// The awk expression receives the raw request on stdin and has these variables:
//   method, url, host, proto, content_type, body_len, headers
//
// If the awk expression prints any output, the filter matches.
func ParseFilterSpec(spec string) (FilterField, string, error) {
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) != 2 || parts[1] == "" {
		return 0, "", fmt.Errorf("format must be field:pattern or awk:expression")
	}

	field := strings.TrimSpace(strings.ToLower(parts[0]))
	pattern := strings.TrimSpace(parts[1])

	switch field {
	case "host":
		return FilterHost, pattern, nil
	case "url", "path":
		return FilterURL, pattern, nil
	case "method":
		return FilterMethod, pattern, nil
	case "content-type", "ct", "mime":
		return FilterContentType, pattern, nil
	case "body":
		return FilterBody, pattern, nil
	case "header", "headers":
		return FilterHeader, pattern, nil
	case "awk":
		return FilterAwk, pattern, nil
	default:
		return 0, "", fmt.Errorf("unknown field %q (use: host, url, method, content-type, body, header, awk)", field)
	}
}
