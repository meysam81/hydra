// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Package cimdtest serves Client ID Metadata Documents to tests under their
// real client_ids (https://claude.ai/...), without touching the network or
// loosening the client_id rules.
package cimdtest

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Response is what the server answers for one client_id.
type Response struct {
	Status int // 200 when zero
	Body   []byte
	Header http.Header
	// Block, when set, holds the response until it is closed or the request
	// is cancelled.
	Block chan struct{}
}

// Server is a TLS server keyed by client_id (scheme, host and path of the
// request).
type Server struct {
	*httptest.Server

	mu       sync.Mutex
	docs     map[string]Response
	hits     map[string]int
	inFlight int
	// Default answers client_ids that were not Set; nil means 404.
	Default func(id string) Response
}

// NewServer starts a server that stops with the test.
func NewServer(t testing.TB) *Server {
	s := &Server{docs: map[string]Response{}, hits: map[string]int{}}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	id := "https://" + r.Host + r.URL.RequestURI()
	s.mu.Lock()
	s.hits[id]++
	s.inFlight++
	res, ok := s.docs[id]
	if !ok && s.Default != nil {
		res, ok = s.Default(id), true
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.inFlight--
		s.mu.Unlock()
	}()
	if !ok {
		http.NotFound(w, r)
		return
	}
	if res.Block != nil {
		select {
		case <-res.Block:
		case <-r.Context().Done():
			return
		}
	}
	for k, v := range res.Header {
		w.Header()[k] = v
	}
	if res.Status != 0 {
		w.WriteHeader(res.Status)
	}
	_, _ = w.Write(res.Body)
}

// Set answers id with res from now on.
func (s *Server) Set(id string, res Response) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.docs[id] = res
}

// Hits is how many requests reached id.
func (s *Server) Hits(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[id]
}

// InFlight is how many requests are being answered right now.
func (s *Server) InFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inFlight
}

// Transport is an HTTP client that sends every request to srv whatever host
// its URL names, trusts srv's certificate for any name and, like
// cimd.NewHTTPClient, never follows a redirect.
func Transport(srv *httptest.Server) *http.Client {
	tr := srv.Client().Transport.(*http.Transport).Clone()
	addr := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	// A name Go's httptest certificate carries.
	tr.TLSClientConfig.ServerName = "example.com"
	return &http.Client{
		Transport:     tr,
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
