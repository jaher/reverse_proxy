package main

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
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
	}
	return "unknown"
}

// InterceptFilter is a single match rule.
type InterceptFilter struct {
	Field   FilterField
	Pattern *regexp.Regexp
	Raw     string // original pattern string for display
}

func (f *InterceptFilter) String() string {
	return fmt.Sprintf("%s =~ /%s/", f.Field, f.Raw)
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

// AddFilter adds a new intercept filter. Returns an error if the regex is invalid.
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
// If filters are set, at least one must match.
func (it *Interceptor) ShouldIntercept(conn *Connection, data []byte) bool {
	it.mu.Lock()
	filters := make([]InterceptFilter, len(it.filters))
	copy(filters, it.filters)
	it.mu.Unlock()

	// No filters = intercept everything
	if len(filters) == 0 {
		return true
	}

	parsed := ParseHTTPRequest(data)

	for _, f := range filters {
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
			// Match against all headers concatenated
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

		if f.Pattern.MatchString(value) {
			return true
		}
	}

	return false
}

// Submit sends a request for interception and blocks until the UI responds.
// Returns the (possibly modified) data and whether to forward.
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

// ParseFilterSpec parses a "field:pattern" string into a FilterField and pattern.
// Supported fields: host, url, method, content-type, body, header
func ParseFilterSpec(spec string) (FilterField, string, error) {
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) != 2 || parts[1] == "" {
		return 0, "", fmt.Errorf("format must be field:pattern (e.g. host:example\\.com)")
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
	default:
		return 0, "", fmt.Errorf("unknown field %q (use: host, url, method, content-type, body, header)", field)
	}
}
