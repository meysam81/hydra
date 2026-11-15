// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/spec"
	"github.com/ory/x/configx"
	"github.com/ory/x/contextx"
	"github.com/ory/x/logrusx"
)

func TestCIMDConfigDefaults(t *testing.T) {
	ctx := t.Context()

	c := newProvider(t)
	assert.False(t, c.CIMDEnabled(ctx))
	minTTL, maxTTL := c.CIMDCacheTTL(ctx)
	assert.Equal(t, 5*time.Minute, minTTL)
	assert.Equal(t, 24*time.Hour, maxTTL)

	c = newProvider(t, configx.WithValues(map[string]any{
		KeyCIMDEnabled: true,
		KeyCIMDMinTTL:  "1m",
		KeyCIMDMaxTTL:  "1h",
	}))
	assert.True(t, c.CIMDEnabled(ctx))
	minTTL, maxTTL = c.CIMDCacheTTL(ctx)
	assert.Equal(t, time.Minute, minTTL)
	assert.Equal(t, time.Hour, maxTTL)

	_, err := New(ctx, logrusx.New("", ""), contextx.NewTestConfigProvider(spec.ConfigValidationSchema), configx.WithValue(KeyCIMDMinTTL, "abc"))
	require.Error(t, err, "the schema must refuse a non-duration min_ttl")
}

func TestValidateCIMDRequiresSSRFGuard(t *testing.T) {
	ctx := t.Context()
	base := map[string]any{KeyIssuerURL: "https://op.example", KeyCIMDEnabled: true}
	with := func(extra map[string]any) map[string]any {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	c := newProvider(t, configx.WithValues(with(map[string]any{KeyClientHTTPNoPrivateIPRanges: false})))
	err := Validate(ctx, logrusx.New("", ""), c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disallow_private_ip_ranges")

	c = newProvider(t, configx.WithValues(with(map[string]any{
		KeyClientHTTPNoPrivateIPRanges:      true,
		KeyClientHTTPPrivateIPExceptionURLs: []string{"https://x.example/*"},
	})))
	err = Validate(ctx, logrusx.New("", ""), c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "private_ip_exception_urls")

	c = newProvider(t, configx.WithValues(with(map[string]any{KeyClientHTTPNoPrivateIPRanges: true})))
	require.NoError(t, Validate(ctx, logrusx.New("", ""), c))

	// The switch off: the guard does not apply.
	c = newProvider(t, configx.WithValues(map[string]any{KeyIssuerURL: "https://op.example"}))
	require.NoError(t, Validate(ctx, logrusx.New("", ""), c))
}
