// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package cimd

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"code.dny.dev/ssrf"
	"github.com/pkg/errors"
)

// fetchTimeout bounds one document fetch, connect to last byte.
const fetchTimeout = 5 * time.Second

// ErrTransient is a fetch that failed for a reason that may pass: a network
// error, a timeout or a status other than 200 (redirects included, §6).
var ErrTransient = errors.New("cimd: client metadata document unavailable")

// NewHTTPClient is the client documents are fetched with (§6, §10.7, §11):
// it dials only global unicast addresses on port 443 (checked on the resolved
// address at dial time, so DNS rebinding cannot reach a private range), uses
// no proxy, follows no redirect, keeps no cookies, retries nothing and sends
// no tracing headers.
func NewHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: fetchTimeout, Control: ssrf.New(ssrf.WithPorts(443)).Safe}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dialer.DialContext,
			TLSHandshakeTimeout:    fetchTimeout,
			ResponseHeaderTimeout:  fetchTimeout,
			MaxResponseHeaderBytes: 16 << 10,
			ForceAttemptHTTP2:      true,
		},
		Timeout:       fetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Fetcher downloads metadata documents and says how long each may be used.
type Fetcher struct {
	HTTP *http.Client
	// MinTTL and MaxTTL clamp the lifetime the response's cache headers ask
	// for (§6.2); no-store and no-cache count as zero, so the floor applies.
	MinTTL, MaxTTL time.Duration
}

// Fetch GETs the document at id. body is at most MaxDocumentSize bytes;
// expiresAt is now plus the clamped cache lifetime.
func (f *Fetcher) Fetch(ctx context.Context, id string, now time.Time) (body []byte, expiresAt time.Time, err error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, id, nil)
	if err != nil {
		return nil, time.Time{}, invalid("client_id is not a URL that can be requested")
	}
	req.Header.Set("Accept", "application/json")

	res, err := f.HTTP.Do(req)
	if err != nil {
		return nil, time.Time{}, errors.Wrap(ErrTransient, err.Error())
	}
	defer res.Body.Close() //nolint:errcheck

	if res.StatusCode != http.StatusOK {
		return nil, time.Time{}, errors.Wrapf(ErrTransient, "status %d", res.StatusCode)
	}
	body, err = io.ReadAll(io.LimitReader(res.Body, MaxDocumentSize+1))
	if err != nil {
		return nil, time.Time{}, errors.Wrap(ErrTransient, err.Error())
	}
	if len(body) > MaxDocumentSize {
		return nil, time.Time{}, invalid("document is larger than %d bytes", MaxDocumentSize)
	}
	return body, now.Add(f.clamp(lifetime(res.Header, now))), nil
}

func (f *Fetcher) clamp(d time.Duration) time.Duration {
	return min(max(d, f.MinTTL), f.MaxTTL)
}

// lifetime is what the response's cache headers allow: max-age, else
// Expires, else nothing; no-store and no-cache mean nothing.
func lifetime(h http.Header, now time.Time) time.Duration {
	maxAge := time.Duration(-1)
	for _, directive := range strings.Split(h.Get("Cache-Control"), ",") {
		d := strings.ToLower(strings.TrimSpace(directive))
		switch {
		case d == "no-store" || d == "no-cache":
			return 0
		case strings.HasPrefix(d, "max-age="):
			if n, err := strconv.Atoi(strings.TrimPrefix(d, "max-age=")); err == nil && n >= 0 {
				maxAge = time.Duration(n) * time.Second
			}
		}
	}
	if maxAge >= 0 {
		return maxAge
	}
	if exp, err := http.ParseTime(h.Get("Expires")); err == nil {
		return exp.Sub(now)
	}
	return 0
}
