package main

import "sync"

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

// Interceptor manages the intercept toggle and pending request queue.
type Interceptor struct {
	mu      sync.Mutex
	enabled bool
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
