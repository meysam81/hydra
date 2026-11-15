// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package cimd_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/client/cimd"
	"github.com/ory/hydra/v2/client/cimd/cimdtest"
	"github.com/ory/hydra/v2/driver"
	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/x/configx"
	"github.com/ory/x/logrusx"
	"github.com/ory/x/popx"
)

const claudeID = "https://claude.ai/oauth/mcp-oauth-client-metadata"

var cacheHeader = http.Header{"Cache-Control": []string{"public, max-age=300"}}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type stubValidator struct{ err error }

func (v stubValidator) Validate(_ context.Context, c *client.Client) error { return v.err }

type fixture struct {
	reg   *driver.RegistrySQL
	srv   *cimdtest.Server
	clock *clock
	m     *cimd.Manager
}

func newFixture(t *testing.T, v cimd.Validator) *fixture {
	t.Helper()
	reg := testhelpers.NewRegistryMemory(t, driver.WithConfigOptions(configx.WithValues(map[string]any{
		config.KeyIssuerURL:                   "https://oauth2.example.com",
		config.KeyClientHTTPNoPrivateIPRanges: true,
		config.KeyCIMDEnabled:                 true,
	})))
	f := &fixture{reg: reg, srv: cimdtest.NewServer(t), clock: &clock{t: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}}
	if v == nil {
		v = reg.ClientValidator()
	}
	f.m = f.manager(v)
	return f
}

func (f *fixture) manager(v cimd.Validator) *cimd.Manager {
	issuer, _ := url.Parse("https://oauth2.example.com")
	return cimd.NewManager(
		f.reg.Persister(), f.reg.ClientManager(), v,
		&cimd.Fetcher{HTTP: cimdtest.Transport(f.srv.Server), MinTTL: 5 * time.Minute, MaxTTL: 24 * time.Hour},
		cimd.Defaults{Scope: []string{"offline_access", "read"}},
		issuer, f.reg.Logger(), f.clock.Now,
	)
}

func (f *fixture) row(t *testing.T, id string) *client.Client {
	t.Helper()
	c, err := f.reg.ClientManager().GetConcreteClient(t.Context(), id)
	require.NoError(t, err)
	return c
}

func (f *fixture) serveClaude(t *testing.T, redirect string) {
	t.Helper()
	f.srv.Set(claudeID, cimdtest.Response{Header: cacheHeader, Body: []byte(fmt.Sprintf(
		`{"client_id":%q,"client_name":"Claude","redirect_uris":[%q],"token_endpoint_auth_method":"none"}`, claudeID, redirect))})
}

func requireInvalidClient(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.ErrorIs(t, err, fosite.ErrInvalidClient)
}

func TestManagerFirstSightCreatesRow(t *testing.T) {
	f := newFixture(t, nil)
	f.srv.Set(claudeID, cimdtest.Response{Header: cacheHeader, Body: testdata(t, "claude")})

	got, err := f.m.GetClient(t.Context(), claudeID)
	require.NoError(t, err)
	assert.Equal(t, claudeID, got.GetID())

	row := f.row(t, claudeID)
	assert.True(t, row.IsMetadataDocumentClient())
	assert.Equal(t, f.clock.Now().Add(5*time.Minute).Format(time.RFC3339), gjson.GetBytes(row.Metadata, "cimd.expires_at").String())
	assert.Equal(t, f.clock.Now().Format(time.RFC3339), gjson.GetBytes(row.Metadata, "cimd.fetched_at").String())
	assert.Equal(t, "offline_access read", row.Scope)
	assert.Equal(t, 1, f.srv.Hits(claudeID))
}

func TestManagerFreshRowNoFetch(t *testing.T) {
	f := newFixture(t, nil)
	f.serveClaude(t, "https://claude.ai/api/mcp/auth_callback")
	_, err := f.m.GetClient(t.Context(), claudeID)
	require.NoError(t, err)
	f.clock.Add(4 * time.Minute)
	_, err = f.m.GetClient(t.Context(), claudeID)
	require.NoError(t, err)
	assert.Equal(t, 1, f.srv.Hits(claudeID))
}

func TestManagerStaleRefetchUpdates(t *testing.T) {
	f := newFixture(t, nil)
	f.serveClaude(t, "https://claude.ai/one")
	_, err := f.m.GetClient(t.Context(), claudeID)
	require.NoError(t, err)
	created := f.row(t, claudeID).CreatedAt

	f.clock.Add(6 * time.Minute)
	f.serveClaude(t, "https://claude.ai/two")
	got, err := f.m.GetClient(t.Context(), claudeID)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://claude.ai/two"}, got.GetRedirectURIs())

	row := f.row(t, claudeID)
	assert.Equal(t, []string{"https://claude.ai/two"}, []string(row.RedirectURIs))
	assert.True(t, created.Equal(row.CreatedAt), "created_at kept: %s vs %s", created, row.CreatedAt)
	assert.WithinDuration(t, time.Now(), row.UpdatedAt, time.Minute, "pop stamps updated_at with the wall clock")
	assert.Equal(t, 2, f.srv.Hits(claudeID))
}

func TestManagerStaleTransientServesForever(t *testing.T) {
	f := newFixture(t, nil)
	f.serveClaude(t, "https://claude.ai/cb")
	_, err := f.m.GetClient(t.Context(), claudeID)
	require.NoError(t, err)

	f.srv.Set(claudeID, cimdtest.Response{Status: http.StatusInternalServerError})
	for _, d := range []time.Duration{6 * time.Minute, 25 * time.Hour, 30 * 24 * time.Hour} {
		f.clock.Add(d)
		got, err := f.m.GetClient(t.Context(), claudeID)
		require.NoError(t, err, "after %s", d)
		assert.Equal(t, claudeID, got.GetID())
	}
	assert.Equal(t, 4, f.srv.Hits(claudeID))
}

func TestManagerStaleNegativeCache(t *testing.T) {
	f := newFixture(t, nil)
	f.serveClaude(t, "https://claude.ai/cb")
	_, err := f.m.GetClient(t.Context(), claudeID)
	require.NoError(t, err)

	f.srv.Set(claudeID, cimdtest.Response{Status: http.StatusInternalServerError})
	f.clock.Add(6 * time.Minute)
	for range 10 {
		_, err := f.m.GetClient(t.Context(), claudeID)
		require.NoError(t, err)
		f.clock.Add(5 * time.Second)
	}
	assert.Equal(t, 2, f.srv.Hits(claudeID), "one refetch, then 60 s of rest")

	f.clock.Add(20 * time.Second)
	_, err = f.m.GetClient(t.Context(), claudeID)
	require.NoError(t, err)
	assert.Equal(t, 3, f.srv.Hits(claudeID))
}

func TestManagerStaleInvalid(t *testing.T) {
	f := newFixture(t, nil)
	f.serveClaude(t, "https://claude.ai/cb")
	_, err := f.m.GetClient(t.Context(), claudeID)
	require.NoError(t, err)

	f.clock.Add(6 * time.Minute)
	f.srv.Set(claudeID, cimdtest.Response{Header: cacheHeader, Body: []byte(`{"client_id":"https://claude.ai/other","redirect_uris":["https://claude.ai/cb"]}`)})
	_, err = f.m.GetClient(t.Context(), claudeID)
	requireInvalidClient(t, err)
	_, err = f.m.GetClient(t.Context(), claudeID)
	requireInvalidClient(t, err)
	assert.True(t, f.row(t, claudeID).IsMetadataDocumentClient(), "the row is kept")

	f.serveClaude(t, "https://claude.ai/cb")
	f.clock.Add(61 * time.Second)
	_, err = f.m.GetClient(t.Context(), claudeID)
	require.NoError(t, err, "a fixed document restores the client")
}

func TestManagerUnknownNegativeCache(t *testing.T) {
	f := newFixture(t, nil)
	f.srv.Set(claudeID, cimdtest.Response{Status: http.StatusInternalServerError})
	_, err := f.m.GetClient(t.Context(), claudeID)
	requireInvalidClient(t, err)
	f.clock.Add(30 * time.Second)
	_, err = f.m.GetClient(t.Context(), claudeID)
	requireInvalidClient(t, err)
	assert.Equal(t, 1, f.srv.Hits(claudeID))

	f.clock.Add(31 * time.Second)
	f.serveClaude(t, "https://claude.ai/cb")
	_, err = f.m.GetClient(t.Context(), claudeID)
	require.NoError(t, err)
	assert.Equal(t, 2, f.srv.Hits(claudeID))
}

func TestManagerSingleflight(t *testing.T) {
	f := newFixture(t, nil)
	release := make(chan struct{})
	f.srv.Set(claudeID, cimdtest.Response{Header: cacheHeader, Block: release, Body: []byte(fmt.Sprintf(
		`{"client_id":%q,"redirect_uris":["https://claude.ai/cb"]}`, claudeID))})

	first, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = f.m.GetClient(first, claudeID)
	}()
	require.Eventually(t, func() bool { return f.srv.InFlight() == 1 }, 5*time.Second, 10*time.Millisecond)

	errs := make(chan error, 19)
	for range 19 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := f.m.GetClient(context.Background(), claudeID)
			if err == nil && c.GetID() != claudeID {
				err = fmt.Errorf("got %s", c.GetID())
			}
			errs <- err
		}()
	}
	time.Sleep(100 * time.Millisecond)
	cancel()
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err, "cancelling the first caller must not fail the others")
	}
	assert.Equal(t, 1, f.srv.Hits(claudeID))
}

func TestManagerConcurrencyCap(t *testing.T) {
	f := newFixture(t, nil)
	release := make(chan struct{})
	block := true
	var mu sync.Mutex
	f.srv.Default = func(id string) cimdtest.Response {
		mu.Lock()
		defer mu.Unlock()
		r := cimdtest.Response{Header: cacheHeader, Body: []byte(fmt.Sprintf(`{"client_id":%q,"redirect_uris":["https://app.example/cb"]}`, id))}
		if block {
			r.Block = release
		}
		return r
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = f.m.GetClient(context.Background(), fmt.Sprintf("https://app%d.example/c", i))
		}()
	}
	require.Eventually(t, func() bool { return f.srv.InFlight() == 8 }, 5*time.Second, 10*time.Millisecond)

	const ninth = "https://app9.example/c"
	_, err := f.m.GetClient(t.Context(), ninth)
	requireInvalidClient(t, err)
	assert.Equal(t, 0, f.srv.Hits(ninth))

	mu.Lock()
	block = false
	mu.Unlock()
	close(release)
	wg.Wait()

	_, err = f.m.GetClient(t.Context(), ninth)
	require.NoError(t, err, "a capped id is not negative-cached")
}

func TestManagerCreateCap(t *testing.T) {
	f := newFixture(t, nil)
	f.srv.Default = func(id string) cimdtest.Response {
		return cimdtest.Response{Header: cacheHeader, Body: []byte(fmt.Sprintf(`{"client_id":%q,"redirect_uris":["https://app.example/cb"]}`, id))}
	}
	for i := range 60 {
		_, err := f.m.GetClient(t.Context(), fmt.Sprintf("https://app%d.example/c", i))
		require.NoError(t, err, i)
	}
	const last = "https://app60.example/c"
	_, err := f.m.GetClient(t.Context(), last)
	requireInvalidClient(t, err)
	_, err = f.reg.ClientManager().GetConcreteClient(t.Context(), last)
	require.Error(t, err, "no row past the cap")

	f.clock.Add(61 * time.Second)
	_, err = f.m.GetClient(t.Context(), last)
	require.NoError(t, err)
}

func TestManagerNoFetchInTransaction(t *testing.T) {
	f := newFixture(t, nil)
	f.serveClaude(t, "https://claude.ai/cb")
	_, err := f.m.GetClient(t.Context(), claudeID)
	require.NoError(t, err)
	f.clock.Add(6 * time.Minute)

	tx := popx.WithTransaction(t.Context(), f.reg.Persister().Connection(t.Context()))
	got, err := f.m.GetClient(tx, claudeID)
	require.NoError(t, err)
	assert.Equal(t, claudeID, got.GetID())
	assert.Equal(t, 1, f.srv.Hits(claudeID))

	const unknown = "https://unknown.example/c"
	_, err = f.m.GetClient(tx, unknown)
	requireInvalidClient(t, err)
	assert.Equal(t, 0, f.srv.Hits(unknown))
}

func TestManagerAdminRowUntouched(t *testing.T) {
	f := newFixture(t, nil)
	const id = "https://admin.example/c"
	require.NoError(t, f.reg.ClientManager().CreateClient(t.Context(), &client.Client{ID: id, Name: "admin", TokenEndpointAuthMethod: "none", RedirectURIs: []string{"https://admin.example/cb"}}))
	f.srv.Set(id, cimdtest.Response{Header: cacheHeader, Body: []byte(fmt.Sprintf(`{"client_id":%q,"client_name":"other","redirect_uris":["https://x.example/cb"]}`, id))})

	got, err := f.m.GetClient(t.Context(), id)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://admin.example/cb"}, got.GetRedirectURIs())
	assert.Equal(t, 0, f.srv.Hits(id))
	assert.Equal(t, "admin", f.row(t, id).Name)
}

func TestManagerNonURLDelegates(t *testing.T) {
	f := newFixture(t, nil)
	id := uuid.Must(uuid.NewV4()).String()
	require.NoError(t, f.reg.ClientManager().CreateClient(t.Context(), &client.Client{ID: id, TokenEndpointAuthMethod: "none"}))
	got, err := f.m.GetClient(t.Context(), id)
	require.NoError(t, err)
	assert.Equal(t, id, got.GetID())

	_, err = f.m.GetClient(t.Context(), "not-a-client")
	require.Error(t, err)
}

func TestManagerInvalidIDURL(t *testing.T) {
	f := newFixture(t, nil)
	for _, id := range []string{"https://x.example/", "https://x.example:8443/c", "https://oauth2.example.com/c"} {
		_, err := f.m.GetClient(t.Context(), id)
		requireInvalidClient(t, err)
		assert.Equal(t, 0, f.srv.Hits(id), id)
	}
}

func TestFositeClientManagerSwitch(t *testing.T) {
	off := testhelpers.NewRegistryMemory(t)
	_, isManager := off.FositeClientManager().(*cimd.Manager)
	assert.False(t, isManager, "switch off: the persister, unwrapped")
	_, err := off.FositeClientManager().GetClient(t.Context(), claudeID)
	require.Error(t, err)

	on := testhelpers.NewRegistryMemory(t, driver.WithConfigOptions(configx.WithValues(map[string]any{
		config.KeyClientHTTPNoPrivateIPRanges: true,
		config.KeyCIMDEnabled:                 true,
	})))
	m, isManager := on.FositeClientManager().(*cimd.Manager)
	require.True(t, isManager)
	assert.Same(t, m, on.FositeClientManager(), "one manager per registry")
}

// A metadata-document client never authenticates with a shared secret, so
// its stored secret must not be the hash of the empty string (which an
// absent client_secret would match for a private_key_jwt client).
func TestManagerCreatedClientHasUnusableSecret(t *testing.T) {
	f := newFixture(t, stubValidator{})
	const id = "https://chatgpt.com/oauth/client.json"
	f.srv.Set(id, cimdtest.Response{Header: cacheHeader, Body: testdata(t, "chatgpt")})
	_, err := f.m.GetClient(t.Context(), id)
	require.NoError(t, err)

	row := f.row(t, id)
	require.NotEmpty(t, row.Secret)
	assert.Error(t, f.reg.ClientHasher().Compare(t.Context(), []byte(row.Secret), []byte("")), "an empty client_secret must not authenticate")
}

// Concurrent callers of a failing fetch share one result; the failure must
// still be remembered, or the host is fetched again on the next request.
func TestManagerConcurrentFailureNegativeCached(t *testing.T) {
	f := newFixture(t, nil)
	release := make(chan struct{})
	f.srv.Set(claudeID, cimdtest.Response{Status: http.StatusInternalServerError, Block: release})
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = f.m.GetClient(context.Background(), claudeID)
		}()
	}
	require.Eventually(t, func() bool { return f.srv.InFlight() == 1 }, 5*time.Second, 10*time.Millisecond)
	time.Sleep(50 * time.Millisecond) // let the other two join the flight
	close(release)
	wg.Wait()

	_, err := f.m.GetClient(t.Context(), claudeID)
	requireInvalidClient(t, err)
	assert.Equal(t, 1, f.srv.Hits(claudeID), "the shared failure is negative-cached")
}

// With the real validator, a default scope of only openid must not come back
// through Hydra's empty-scope default.
func TestManagerNeverStoresOpenID(t *testing.T) {
	f := newFixture(t, nil)
	issuer, _ := url.Parse("https://oauth2.example.com")
	m := cimd.NewManager(f.reg.Persister(), f.reg.ClientManager(), f.reg.ClientValidator(),
		&cimd.Fetcher{HTTP: cimdtest.Transport(f.srv.Server), MinTTL: 5 * time.Minute, MaxTTL: 24 * time.Hour},
		cimd.Defaults{Scope: []string{"openid"}}, issuer, f.reg.Logger(), f.clock.Now)
	f.serveClaude(t, "https://claude.ai/cb")
	_, err := m.GetClient(t.Context(), claudeID)
	requireInvalidClient(t, err)
	_, err = f.reg.ClientManager().GetConcreteClient(t.Context(), claudeID)
	require.Error(t, err, "no row with a refilled scope")
}

// A config reload can turn the private-range guard off after startup: the
// manager must not keep fetching without it.
func TestFositeClientManagerFailsClosedWithoutGuard(t *testing.T) {
	reg := testhelpers.NewRegistryMemory(t, driver.WithConfigOptions(configx.WithValues(map[string]any{
		config.KeyClientHTTPNoPrivateIPRanges: true,
		config.KeyCIMDEnabled:                 true,
	})))
	_, isManager := reg.FositeClientManager().(*cimd.Manager)
	require.True(t, isManager)

	reg.Config().MustSet(t.Context(), config.KeyClientHTTPNoPrivateIPRanges, false)
	_, isManager = reg.FositeClientManager().(*cimd.Manager)
	assert.False(t, isManager, "guard off: no fetching")

	reg.Config().MustSet(t.Context(), config.KeyClientHTTPNoPrivateIPRanges, true)
	reg.Config().MustSet(t.Context(), config.KeyClientHTTPPrivateIPExceptionURLs, []string{"https://x.example/*"})
	_, isManager = reg.FositeClientManager().(*cimd.Manager)
	assert.False(t, isManager, "exception URLs: no fetching")
}

// idFoldingStore is a database whose id comparison ignores case (a MySQL
// collation): it answers a look-alike id with the stored row.
type idFoldingStore struct{ cimd.Store }

func (s idFoldingStore) GetConcreteClient(ctx context.Context, id string) (*client.Client, error) {
	return s.Store.GetConcreteClient(ctx, strings.ToLower(id))
}

func TestManagerRefusesRowWithAnotherID(t *testing.T) {
	f := newFixture(t, nil)
	f.serveClaude(t, "https://claude.ai/cb")
	_, err := f.m.GetClient(t.Context(), claudeID)
	require.NoError(t, err)

	issuer, _ := url.Parse("https://oauth2.example.com")
	m := cimd.NewManager(f.reg.Persister(), idFoldingStore{f.reg.ClientManager()}, f.reg.ClientValidator(),
		&cimd.Fetcher{HTTP: cimdtest.Transport(f.srv.Server), MinTTL: 5 * time.Minute, MaxTTL: 24 * time.Hour},
		cimd.Defaults{Scope: []string{"read"}}, issuer, f.reg.Logger(), f.clock.Now)
	const lookAlike = "https://CLAUDE.ai/oauth/mcp-oauth-client-metadata"
	_, err = m.GetClient(t.Context(), lookAlike)
	requireInvalidClient(t, err)
	assert.Zero(t, f.srv.Hits(lookAlike))
}

func TestManagerLogsRejectedIDsAtDebug(t *testing.T) {
	f := newFixture(t, nil)
	hook := &logtest.Hook{}
	l := logrusx.New("", "", logrusx.WithHook(hook), logrusx.ForceLevel(logrus.InfoLevel))
	issuer, _ := url.Parse("https://oauth2.example.com")
	m := cimd.NewManager(f.reg.Persister(), f.reg.ClientManager(), f.reg.ClientValidator(),
		&cimd.Fetcher{HTTP: cimdtest.Transport(f.srv.Server), MinTTL: 5 * time.Minute, MaxTTL: 24 * time.Hour},
		cimd.Defaults{Scope: []string{"read"}}, issuer, l, f.clock.Now)
	outcomes := func() []string {
		var out []string
		for _, e := range hook.AllEntries() {
			if o, ok := e.Data["cimd_outcome"].(string); ok && e.Level <= logrus.InfoLevel {
				out = append(out, o)
			}
		}
		return out
	}

	_, err := m.GetClient(t.Context(), "https://x.example/")
	requireInvalidClient(t, err)
	assert.Empty(t, outcomes(), "a rejected id never reaches the info log")

	f.serveClaude(t, "https://claude.ai/cb")
	_, err = m.GetClient(t.Context(), claudeID)
	require.NoError(t, err)
	assert.Equal(t, []string{"created"}, outcomes())

	// Stale and failing: served from the row, logged at info (the
	// HydraCIMDFetchFailing alert counts it).
	f.clock.Add(6 * time.Minute)
	f.srv.Set(claudeID, cimdtest.Response{Status: http.StatusInternalServerError})
	_, err = m.GetClient(t.Context(), claudeID)
	require.NoError(t, err)
	assert.Contains(t, outcomes(), "stale_served")

	// Create cap: logged at info (the HydraCIMDCapped alert counts it).
	f.srv.Default = func(id string) cimdtest.Response {
		return cimdtest.Response{Header: cacheHeader, Body: []byte(fmt.Sprintf(`{"client_id":%q,"redirect_uris":["https://app.example/cb"]}`, id))}
	}
	for i := range 61 {
		_, _ = m.GetClient(t.Context(), fmt.Sprintf("https://cap%d.example/c", i))
	}
	assert.Contains(t, outcomes(), "capped")
}

// One failed refetch is one stale_served line, however many requests waited
// on it: HydraCIMDFetchFailing counts these lines.
func TestManagerStaleServedLoggedOncePerFlight(t *testing.T) {
	f := newFixture(t, nil)
	hook := &logtest.Hook{}
	l := logrusx.New("", "", logrusx.WithHook(hook), logrusx.ForceLevel(logrus.InfoLevel))
	issuer, _ := url.Parse("https://oauth2.example.com")
	m := cimd.NewManager(f.reg.Persister(), f.reg.ClientManager(), f.reg.ClientValidator(),
		&cimd.Fetcher{HTTP: cimdtest.Transport(f.srv.Server), MinTTL: 5 * time.Minute, MaxTTL: 24 * time.Hour},
		cimd.Defaults{Scope: []string{"read"}}, issuer, l, f.clock.Now)
	f.serveClaude(t, "https://claude.ai/cb")
	_, err := m.GetClient(t.Context(), claudeID)
	require.NoError(t, err)

	f.clock.Add(6 * time.Minute)
	release := make(chan struct{})
	f.srv.Set(claudeID, cimdtest.Response{Status: http.StatusInternalServerError, Block: release})
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.GetClient(context.Background(), claudeID)
			assert.NoError(t, err)
		}()
	}
	require.Eventually(t, func() bool { return f.srv.InFlight() == 1 }, 5*time.Second, 10*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	n := 0
	for _, e := range hook.AllEntries() {
		if e.Data["cimd_outcome"] == "stale_served" {
			n++
		}
	}
	assert.Equal(t, 1, n)
}
