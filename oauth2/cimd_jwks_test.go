// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/driver"
	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/fositex"
	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/x/configx"
)

// While CIMD is on, any document author can make Hydra fetch a jwks_uri, so
// the fetch uses the document client; off, upstream's client is unchanged.
func TestJWKSHTTPClientFollowsTheSwitch(t *testing.T) {
	ctx := t.Context()
	reg := testhelpers.NewRegistryMemory(t, driver.WithConfigOptions(configx.WithValues(map[string]any{
		config.KeyClientHTTPNoPrivateIPRanges: true,
	})))
	cfg, ok := reg.OAuth2ProviderConfig().(*fositex.Config)
	require.True(t, ok)

	assert.Equal(t, 2, cfg.JWKSHTTPClient(ctx).RetryMax, "switch off: upstream client")

	reg.Config().MustSet(ctx, config.KeyCIMDEnabled, true)
	hc := cfg.JWKSHTTPClient(ctx)
	assert.Equal(t, 0, hc.RetryMax)
	require.NotNil(t, hc.HTTPClient.CheckRedirect)
	assert.ErrorIs(t, hc.HTTPClient.CheckRedirect(nil, nil), http.ErrUseLastResponse)
	assert.Equal(t, 5*time.Second, hc.HTTPClient.Timeout)
	tr, ok := hc.HTTPClient.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Nil(t, tr.Proxy)
	assert.True(t, tr.DisableKeepAlives)

	reg.Config().MustSet(ctx, config.KeyCIMDEnabled, false)
	assert.Equal(t, 2, cfg.JWKSHTTPClient(ctx).RetryMax, "switch off again, no restart")
}
