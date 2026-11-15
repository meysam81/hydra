// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/hydra/v2/driver"
	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/hydra/v2/oauth2"
	"github.com/ory/hydra/v2/x"
	"github.com/ory/x/configx"
	"github.com/ory/x/httprouterx"
)

// The discovery document of v26.2.0 before the CIMD patch, for the config
// below. UPDATE_GOLDEN=1 rewrites it.
const discoveryGolden = "testdata/discovery-v26.2.0.golden.json"

func discoveryBody(t *testing.T, cimd bool) []byte {
	t.Helper()
	values := map[string]any{
		config.KeyIssuerURL:                   "https://op.example",
		config.KeyClientHTTPNoPrivateIPRanges: true,
	}
	if cimd {
		values[config.KeyCIMDEnabled] = true
	}
	reg := testhelpers.NewRegistryMemory(t, driver.WithConfigOptions(configx.WithValues(values)))
	testhelpers.MustEnsureRegistryKeys(t, reg, x.OpenIDConnectKeyName)

	r := httprouterx.NewTestRouterAdminWithPrefix(t)
	oauth2.NewHandler(reg).SetPublicRoutes(r.ToPublic(), func(h http.Handler) http.Handler { return h })
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	res, err := http.Get(ts.URL + oauth2.OauthAuthorizationServerPath)
	require.NoError(t, err)
	defer res.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, res.StatusCode)
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return body
}

func TestDiscoveryCIMDFlags(t *testing.T) {
	t.Run("switch off is byte-identical to v26.2.0", func(t *testing.T) {
		body := discoveryBody(t, false)
		if os.Getenv("UPDATE_GOLDEN") == "1" {
			require.NoError(t, os.WriteFile(discoveryGolden, body, 0o600))
		}
		golden, err := os.ReadFile(discoveryGolden)
		require.NoError(t, err)
		assert.Equal(t, string(golden), string(body))
		assert.False(t, gjson.GetBytes(body, "client_id_metadata_document_supported").Exists())
		assert.False(t, gjson.GetBytes(body, "authorization_response_iss_parameter_supported").Exists())
	})

	t.Run("switch on adds both flags and nothing else", func(t *testing.T) {
		body := discoveryBody(t, true)
		assert.True(t, gjson.GetBytes(body, "client_id_metadata_document_supported").Bool())
		assert.True(t, gjson.GetBytes(body, "authorization_response_iss_parameter_supported").Bool())

		golden, err := os.ReadFile(discoveryGolden)
		require.NoError(t, err)
		gjson.ParseBytes(golden).ForEach(func(k, v gjson.Result) bool {
			assert.JSONEq(t, v.Raw, gjson.GetBytes(body, k.String()).Raw, k.String())
			return true
		})
		assert.Len(t, gjson.ParseBytes(body).Map(), len(gjson.ParseBytes(golden).Map())+2)
	})
}

func TestAuthorizationResponseIssuer(t *testing.T) {
	for _, on := range []bool{false, true} {
		values := map[string]any{config.KeyIssuerURL: "https://op.example", config.KeyClientHTTPNoPrivateIPRanges: true, config.KeyCIMDEnabled: on}
		reg := testhelpers.NewRegistryMemory(t, driver.WithConfigOptions(configx.WithValues(values)))
		p, ok := reg.OAuth2ProviderConfig().(fosite.AuthorizationResponseIssuerProvider)
		require.True(t, ok, "Hydra's fosite config implements the provider")
		got := p.GetAuthorizationResponseIssuer(t.Context())
		if !on {
			assert.Empty(t, got, "no iss while CIMD is off")
			continue
		}
		assert.Equal(t, gjson.GetBytes(discoveryBody(t, true), "issuer").String(), got, "iss is the discovery issuer, byte for byte")
	}
}
