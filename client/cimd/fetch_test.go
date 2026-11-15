// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package cimd_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/client/cimd"
)

var fetchNow = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

// fetcher talks to srv with the same no-redirect policy as NewHTTPClient.
func fetcher(srv *httptest.Server) *cimd.Fetcher {
	hc := srv.Client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cimd.Fetcher{HTTP: hc, MinTTL: 5 * time.Minute, MaxTTL: 24 * time.Hour}
}

func TestFetchRequest(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		for _, h := range []string{"Cookie", "Traceparent", "Tracestate", "Authorization"} {
			assert.Empty(t, r.Header.Get(h), h)
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	body, _, err := fetcher(srv).Fetch(t.Context(), srv.URL+"/c", fetchNow)
	require.NoError(t, err)
	assert.Equal(t, `{}`, string(body))
}

func TestFetchTTL(t *testing.T) {
	for name, tc := range map[string]struct {
		headers map[string]string
		want    time.Duration
	}{
		"max-age=300":         {map[string]string{"Cache-Control": "public, max-age=300"}, 5 * time.Minute},
		"max-age=60 floored":  {map[string]string{"Cache-Control": "max-age=60"}, 5 * time.Minute},
		"max-age capped":      {map[string]string{"Cache-Control": "max-age=999999"}, 24 * time.Hour},
		"max-age=7200":        {map[string]string{"Cache-Control": "max-age=7200"}, 2 * time.Hour},
		"no-store":            {map[string]string{"Cache-Control": "no-store,no-cache,max-age=0"}, 5 * time.Minute},
		"no-cache max-age":    {map[string]string{"Cache-Control": "no-cache, max-age=3600"}, 5 * time.Minute},
		"expires in two hour": {map[string]string{"Expires": fetchNow.Add(2 * time.Hour).Format(http.TimeFormat)}, 2 * time.Hour},
		"nothing":             {nil, 5 * time.Minute},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tc.headers {
					w.Header().Set(k, v)
				}
				_, _ = w.Write([]byte(`{}`))
			}))
			t.Cleanup(srv.Close)

			_, expires, err := fetcher(srv).Fetch(t.Context(), srv.URL+"/c", fetchNow)
			require.NoError(t, err)
			assert.Equal(t, fetchNow.Add(tc.want), expires)
		})
	}
}

func TestFetchStatus(t *testing.T) {
	targetHit := false
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/target", http.StatusFound)
	})
	mux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		targetHit = true
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/404", http.NotFound)
	mux.HandleFunc("/500", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	for _, p := range []string{"/redirect", "/404", "/500"} {
		_, _, err := fetcher(srv).Fetch(t.Context(), srv.URL+p, fetchNow)
		assert.ErrorIs(t, err, cimd.ErrTransient, p)
	}
	assert.False(t, targetHit, "a redirect is never followed")
}

func TestFetchSize(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := cimd.MaxDocumentSize
		if r.URL.Path == "/big" {
			n++
		}
		_, _ = w.Write([]byte(strings.Repeat(" ", n)))
	}))
	t.Cleanup(srv.Close)

	body, _, err := fetcher(srv).Fetch(t.Context(), srv.URL+"/ok", fetchNow)
	require.NoError(t, err)
	assert.Len(t, body, cimd.MaxDocumentSize)

	_, _, err = fetcher(srv).Fetch(t.Context(), srv.URL+"/big", fetchNow)
	assert.ErrorIs(t, err, cimd.ErrInvalid)
}

func TestFetchTimeout(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	t.Cleanup(srv.Close)

	start := time.Now()
	_, _, err := fetcher(srv).Fetch(t.Context(), srv.URL+"/slow", fetchNow)
	assert.ErrorIs(t, err, cimd.ErrTransient)
	assert.Less(t, time.Since(start), 6*time.Second)
}

func TestNewHTTPClientRefusesPrivateAndRedirects(t *testing.T) {
	hit := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	t.Cleanup(srv.Close)

	hc := cimd.NewHTTPClient()
	f := &cimd.Fetcher{HTTP: hc, MinTTL: time.Minute, MaxTTL: time.Hour}
	_, _, err := f.Fetch(context.Background(), srv.URL+"/c", fetchNow)
	assert.ErrorIs(t, err, cimd.ErrTransient)
	assert.False(t, hit, "the guarded dialer never reaches a loopback address")

	require.NotNil(t, hc.CheckRedirect)
	assert.ErrorIs(t, hc.CheckRedirect(nil, nil), http.ErrUseLastResponse)
	assert.Nil(t, hc.Jar)
	assert.Equal(t, 5*time.Second, hc.Timeout)
}

// A document fetch is one-shot: an idle connection per attacker-chosen host
// would pile up file descriptors and memory.
func TestNewHTTPClientKeepsNoIdleConnections(t *testing.T) {
	tr, ok := cimd.NewHTTPClient().Transport.(*http.Transport)
	require.True(t, ok)
	assert.True(t, tr.DisableKeepAlives)
}
