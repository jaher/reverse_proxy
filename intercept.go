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

// InterceptFilter is a single match rule — regex-based or awk-based.
type InterceptFilter struct {
	Field   FilterField
	Pattern *regexp.Regexp // nil for awk filters
	AwkExpr string        // non-empty for awk filters
	Rewrite bool          // if true, awk output replaces the request data (auto-forward)
	Raw     string        // original pattern/expression for display
}

func (f *InterceptFilter) String() string {
	if f.Field == FilterAwk {
		mode := "match"
		if f.Rewrite {
			mode = "rewrite"
		}
		return fmt.Sprintf("awk[%s] { %s }", mode, f.Raw)
	}
	return fmt.Sprintf("%s =~ /%s/", f.Field, f.Raw)
}

// MatchRegex tests the filter against a string value.
func (f *InterceptFilter) MatchRegex(value string) bool {
	if f.Pattern == nil {
		return false
	}
	return f.Pattern.MatchString(value)
}

// RunAwk executes the awk expression against request data.
// Returns (output, matched). Output is the awk stdout; matched is true if any output was produced.
// If sandbox is true, awk is run with --sandbox to disable system(), pipes, and I/O redirection.
func (f *InterceptFilter) RunAwk(conn *Connection, data []byte, parsed *ParsedHTTP, sandbox bool) ([]byte, bool) {
	if f.AwkExpr == "" {
		return nil, false
	}

	vars := buildAwkVars(conn, data, parsed)
	var args []string
	if sandbox {
		args = append(args, "--sandbox")
	}
	args = append(args, vars...)
	args = append(args, f.AwkExpr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "awk", args...)
	cmd.Stdin = bytes.NewReader(data)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		return nil, false
	}

	if stdout.Len() == 0 {
		return nil, false
	}
	return stdout.Bytes(), true
}

func buildAwkVars(conn *Connection, data []byte, parsed *ParsedHTTP) []string {
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

	return vars
}

// FilterResult describes how a request should be handled after filter evaluation.
type FilterResult struct {
	Matched      bool   // at least one filter matched
	Rewritten    bool   // an awk rewrite filter produced replacement data
	RewriteData  []byte // the replacement data (only if Rewritten)
}

// Interceptor manages the intercept toggle, filters, and pending request queue.
type Interceptor struct {
	mu         sync.Mutex
	enabled    bool
	filters    []InterceptFilter
	queue      chan *InterceptRequest
	AwkSandbox bool // if true, run awk with --sandbox (disables system(), pipes, I/O redirection)
}

func NewInterceptor() *Interceptor {
	return &Interceptor{
		queue:      make(chan *InterceptRequest, 64),
		AwkSandbox: true, // safe by default
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

// AddAwkFilter adds an awk-based filter.
// If rewrite is true, the awk output replaces the request data and auto-forwards.
// If rewrite is false, a match just pauses for manual editing (like regex filters).
func (it *Interceptor) AddAwkFilter(expr string, rewrite bool) error {
	// Validate syntax by running awk with empty input
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	args := []string{}
	it.mu.Lock()
	if it.AwkSandbox {
		args = append(args, "--sandbox")
	}
	it.mu.Unlock()
	args = append(args, expr)
	cmd := exec.CommandContext(ctx, "awk", args...)
	cmd.Stdin = strings.NewReader("")
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
			return fmt.Errorf("awk syntax error in %q", expr)
		}
	}

	it.mu.Lock()
	defer it.mu.Unlock()
	it.filters = append(it.filters, InterceptFilter{
		Field:   FilterAwk,
		AwkExpr: expr,
		Rewrite: rewrite,
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

// ProcessFilters evaluates all filters against the request.
// Returns a FilterResult describing the outcome:
//   - No filters: Matched=true (intercept everything)
//   - Awk rewrite filter matched: Matched=true, Rewritten=true, RewriteData=awk output
//   - Regex or awk match filter: Matched=true, Rewritten=false (pause for editing)
//   - No filter matched: Matched=false
//
// Rewrite filters take priority: if one matches, its output is used immediately.
func (it *Interceptor) ProcessFilters(conn *Connection, data []byte) FilterResult {
	it.mu.Lock()
	filters := make([]InterceptFilter, len(it.filters))
	copy(filters, it.filters)
	it.mu.Unlock()

	if len(filters) == 0 {
		return FilterResult{Matched: true}
	}

	it.mu.Lock()
	sandbox := it.AwkSandbox
	it.mu.Unlock()

	parsed := ParseHTTPRequest(data)
	anyMatch := false

	for i := range filters {
		f := &filters[i]

		if f.Field == FilterAwk {
			output, matched := f.RunAwk(conn, data, parsed, sandbox)
			if matched {
				if f.Rewrite {
					return FilterResult{
						Matched:     true,
						Rewritten:   true,
						RewriteData: output,
					}
				}
				anyMatch = true
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
			anyMatch = true
		}
	}

	return FilterResult{Matched: anyMatch}
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
// Regex filters:   field:pattern          e.g. host:example\.com
// Awk match:       awk:expression         e.g. awk:method == "POST" && url ~ /login/
// Awk rewrite:     awk!:expression        e.g. awk!:{ gsub(/staging/, "prod"); print }
//
// awk: filters pause matching requests for manual editing.
// awk!: filters auto-rewrite: awk output replaces the request and forwards immediately.
func ParseFilterSpec(spec string) (FilterField, string, error) {
	// Check for awk!: prefix (rewrite mode) before splitting
	if strings.HasPrefix(spec, "awk!:") {
		pattern := strings.TrimSpace(spec[5:])
		if pattern == "" {
			return 0, "", fmt.Errorf("awk!: requires an expression")
		}
		// We'll use a special marker to distinguish rewrite from match
		return FilterAwk, "!" + pattern, nil
	}

	parts := strings.SplitN(spec, ":", 2)
	if len(parts) != 2 || parts[1] == "" {
		return 0, "", fmt.Errorf("format must be field:pattern, awk:expression, or awk!:expression")
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
		return 0, "", fmt.Errorf("unknown field %q (use: host, url, method, content-type, body, header, awk, awk!)", field)
	}
}
