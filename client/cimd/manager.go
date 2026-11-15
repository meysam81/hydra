// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package cimd

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"golang.org/x/sync/singleflight"

	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/x/logrusx"
	"github.com/ory/x/popx"
	"github.com/ory/x/sqlcon"
)

const (
	// negativeTTL is how long a failed fetch is not repeated (§6.2 MAY).
	negativeTTL = time.Minute
	// negativeCacheSize bounds the failed-fetch memory.
	negativeCacheSize = 10_000
	// maxConcurrentFetches bounds simultaneous document fetches per process.
	maxConcurrentFetches = 8
	// maxCreatesPerMinute bounds new metadata-document clients per process.
	maxCreatesPerMinute = 60
)

// Store is the client storage the manager reads and writes.
type Store interface {
	GetConcreteClient(ctx context.Context, id string) (*client.Client, error)
	CreateClient(ctx context.Context, c *client.Client) error
	UpdateClient(ctx context.Context, c *client.Client) error
}

// Validator is Hydra's client validator.
type Validator interface {
	Validate(ctx context.Context, c *client.Client) error
}

// errInvalidClient is every refusal fosite sees; it rewraps it as
// invalid_client anyway, and fetch details stay in the log.
var errInvalidClient = fosite.ErrInvalidClient.WithHint("The OAuth 2.0 Client could not be resolved from its client metadata document.")

// errCapped is a fetch or create the per-process bounds refused.
var errCapped = errors.New("cimd: too many concurrent fetches or new clients")

type negative struct {
	until   time.Time
	invalid bool
}

// Manager is the fosite.ClientManager of a Hydra with CIMD on: an https
// client_id resolves to the hydra_client row its metadata document describes,
// fetched on first sight and again once the row's cache lifetime is over.
// Every other client_id goes to inner.
type Manager struct {
	inner  fosite.ClientManager
	store  Store
	v      Validator
	f      *Fetcher
	d      Defaults
	issuer *url.URL
	l      *logrusx.Logger
	now    func() time.Time

	group singleflight.Group
	sem   chan struct{}

	mu          sync.Mutex
	negative    map[string]negative
	windowStart time.Time
	created     int
}

var _ fosite.ClientManager = (*Manager)(nil)

// NewManager wraps inner, the persister's client manager.
func NewManager(inner fosite.ClientManager, store Store, v Validator, f *Fetcher, d Defaults, issuer *url.URL, l *logrusx.Logger, now func() time.Time) *Manager {
	return &Manager{
		inner: inner, store: store, v: v, f: f, d: d, issuer: issuer, l: l, now: now,
		sem:      make(chan struct{}, maxConcurrentFetches),
		negative: map[string]negative{},
	}
}

func (m *Manager) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return m.inner.ClientAssertionJWTValid(ctx, jti)
}

func (m *Manager) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return m.inner.SetClientAssertionJWT(ctx, jti, exp)
}

// GetClient resolves id (spec C10/C11).
func (m *Manager) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	if !IsClientIDURL(id) {
		return m.inner.GetClient(ctx, id)
	}
	if err := ValidateClientIDURL(id, m.issuer); err != nil {
		m.log(id, "invalid", err)
		return nil, errInvalidClient
	}

	row, err := m.store.GetConcreteClient(ctx, id)
	switch {
	case errors.Is(err, sqlcon.ErrNoRows):
		row = nil
	case err != nil:
		return nil, err
	case !row.IsMetadataDocumentClient():
		return row, nil // admin-managed: never fetched, never overwritten
	}

	now := m.now()
	if row != nil && now.Before(expiresAt(row)) {
		return row, nil
	}
	// Revocation authenticates its client inside a database transaction:
	// never hold one open across a network fetch.
	if popx.InTransaction(ctx) {
		if row != nil {
			return row, nil
		}
		return nil, errInvalidClient
	}
	if neg, ok := m.negativeHit(id, now); ok {
		if row != nil && !neg.invalid {
			return row, nil
		}
		return nil, errInvalidClient
	}
	if row == nil && !m.createAllowed(now) {
		m.log(id, "capped", nil)
		return nil, errInvalidClient
	}

	// One fetch per id however many requests wait for it, detached from the
	// first caller so its cancellation does not fail the others.
	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*fetchTimeout)
	defer cancel()
	v, err, shared := m.group.Do(id, func() (any, error) { return m.resolve(fetchCtx, id) })
	if err == nil {
		return v.(*client.Client), nil
	}
	switch {
	case errors.Is(err, errCapped):
		if row != nil {
			return row, nil
		}
		return nil, errInvalidClient
	case errors.Is(err, ErrInvalid):
		if !shared {
			m.remember(id, now, true)
		}
		return nil, errInvalidClient
	case errors.Is(err, ErrTransient):
		if !shared {
			m.remember(id, now, false)
		}
		if row != nil {
			if !shared {
				m.log(id, "stale_served", err)
			}
			return row, nil
		}
		return nil, errInvalidClient
	default:
		return nil, err
	}
}

// resolve fetches, validates and stores id's document.
func (m *Manager) resolve(ctx context.Context, id string) (_ *client.Client, err error) {
	start := time.Now()
	outcome := ""
	defer func() { m.logFetch(id, outcome, start, err) }()

	select {
	case m.sem <- struct{}{}:
		defer func() { <-m.sem }()
	default:
		outcome = "capped"
		return nil, errCapped
	}

	now := m.now()
	body, expires, err := m.f.Fetch(ctx, id, now)
	if err != nil {
		outcome = outcomeOf(err)
		return nil, err
	}
	c, err := ParseDocument(id, body, m.d)
	if err != nil {
		outcome = "invalid"
		return nil, err
	}
	c.Metadata = []byte(fmt.Sprintf(`{%q:{"fetched_at":%q,"expires_at":%q}}`,
		client.MetadataDocumentKey, now.UTC().Format(time.RFC3339), expires.UTC().Format(time.RFC3339)))
	if err := m.v.Validate(ctx, c); err != nil {
		// The validator resolves jwks_uri: a DNS failure is not a verdict.
		if dns := new(net.DNSError); errors.As(err, &dns) {
			outcome = "unavailable"
			return nil, errors.Wrap(ErrTransient, err.Error())
		}
		outcome = "invalid"
		return nil, errors.Wrap(ErrInvalid, err.Error())
	}

	existing, err := m.store.GetConcreteClient(ctx, id)
	switch {
	case err == nil && !existing.IsMetadataDocumentClient():
		outcome = "admin_row"
		return existing, nil
	case err == nil:
		c.CreatedAt, c.UpdatedAt = existing.CreatedAt, now
		if err := m.store.UpdateClient(ctx, c); err != nil {
			outcome = "store_error"
			return nil, err
		}
		outcome = "updated"
		return m.store.GetConcreteClient(ctx, id)
	case !errors.Is(err, sqlcon.ErrNoRows):
		outcome = "store_error"
		return nil, err
	}

	if !m.takeCreate(now) {
		outcome = "capped"
		return nil, errCapped
	}
	c.CreatedAt, c.UpdatedAt = now, now
	if err := m.store.CreateClient(ctx, c); err != nil {
		if !errors.Is(err, sqlcon.ErrUniqueViolation) {
			outcome = "store_error"
			return nil, err
		}
		outcome = "created_elsewhere" // another replica won the insert
	} else {
		outcome = "created"
	}
	return m.store.GetConcreteClient(ctx, id)
}

func outcomeOf(err error) string {
	if errors.Is(err, ErrInvalid) {
		return "invalid"
	}
	return "unavailable"
}

func expiresAt(c *client.Client) time.Time {
	return gjson.GetBytes(c.Metadata, client.MetadataDocumentKey+".expires_at").Time()
}

func (m *Manager) negativeHit(id string, now time.Time) (negative, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.negative[id]
	if !ok || !now.Before(n.until) {
		return negative{}, false
	}
	return n, true
}

// remember records a failed fetch. Past the size bound, expired entries are
// pruned; if none expired, the failure is not remembered.
func (m *Manager) remember(id string, now time.Time, invalid bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.negative) >= negativeCacheSize {
		for k, n := range m.negative {
			if !now.Before(n.until) {
				delete(m.negative, k)
			}
		}
		if len(m.negative) >= negativeCacheSize {
			return
		}
	}
	m.negative[id] = negative{until: now.Add(negativeTTL), invalid: invalid}
}

func (m *Manager) rollWindow(now time.Time) {
	if now.Sub(m.windowStart) >= time.Minute || now.Before(m.windowStart) {
		m.windowStart, m.created = now, 0
	}
}

func (m *Manager) createAllowed(now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rollWindow(now)
	return m.created < maxCreatesPerMinute
}

func (m *Manager) takeCreate(now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rollWindow(now)
	if m.created >= maxCreatesPerMinute {
		return false
	}
	m.created++
	return true
}

func (m *Manager) log(id, outcome string, err error) {
	e := m.l.WithField("client_id", id).WithField("cimd_outcome", outcome)
	if err != nil {
		e = e.WithField("reason", err.Error())
	}
	e.Info("client metadata document")
}

func (m *Manager) logFetch(id, outcome string, start time.Time, err error) {
	e := m.l.WithField("client_id", id).
		WithField("cimd_outcome", outcome).
		WithField("duration_ms", time.Since(start).Milliseconds())
	if err != nil {
		e = e.WithField("reason", err.Error())
	}
	e.Info("client metadata document fetch")
}
