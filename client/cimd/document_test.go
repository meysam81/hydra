// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package cimd_test

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/client/cimd"
)

var defaults = cimd.Defaults{Scope: []string{"offline_access", "read", "domains:add"}}

// realClients maps each testdata document to the client_id it is served at.
var realClients = map[string]string{
	"claude":      "https://claude.ai/oauth/mcp-oauth-client-metadata",
	"claude-code": "https://claude.ai/oauth/claude-code-client-metadata",
	"chatgpt":     "https://chatgpt.com/oauth/client.json",
	"codex":       "https://chatgpt.com/oauth/codex/client.json",
	"vscode":      "https://vscode.dev/oauth/client-metadata.json",
}

func testdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name + ".json")
	require.NoError(t, err)
	return b
}

func TestValidateClientIDURL(t *testing.T) {
	issuer, _ := url.Parse("https://oauth2.example.com")
	for _, id := range realClients {
		assert.NoError(t, cimd.ValidateClientIDURL(id, issuer), id)
	}
	for _, id := range []string{
		"http://x.com/c",
		"https://x.com",
		"https://x.com/",
		"https://u:p@x.com/c",
		"https://x.com:443/c",
		"https://x.com:8443/c",
		"https://x.com/c#f",
		"https://x.com/c?a=1",
		"https://x.com/a/../c",
		"https://x.com/./c",
		"https://x.com/" + strings.Repeat("a", 256-len("https://x.com/")),
		"https://oauth2.example.com/c",
		"https://oauth2.example.com./c",
	} {
		err := cimd.ValidateClientIDURL(id, issuer)
		assert.ErrorIs(t, err, cimd.ErrInvalid, id)
	}
}

func TestParseDocumentRealClients(t *testing.T) {
	for name, id := range realClients {
		c, err := cimd.ParseDocument(id, testdata(t, name), defaults)
		require.NoError(t, err, name)
		assert.Equal(t, id, c.ID, name)
		assert.Empty(t, c.LogoURI, name)
		assert.False(t, c.SkipConsent, name)
		assert.Empty(t, c.RequestURIs, name)
		assert.Empty(t, c.SectorIdentifierURI, name)
		assert.Empty(t, c.Secret, name)
		assert.Empty(t, c.Metadata, name)
		assert.Equal(t, []string{"code"}, []string(c.ResponseTypes), name)
		assert.Equal(t, "offline_access read domains:add", c.Scope, name)
	}

	claude, err := cimd.ParseDocument(realClients["claude"], testdata(t, "claude"), defaults)
	require.NoError(t, err)
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, []string(claude.GrantTypes))
	assert.Equal(t, "none", claude.TokenEndpointAuthMethod)
	assert.Equal(t, "Claude", claude.Name)
	assert.Equal(t, "https://claude.ai", claude.ClientURI)

	chatgpt, err := cimd.ParseDocument(realClients["chatgpt"], testdata(t, "chatgpt"), defaults)
	require.NoError(t, err)
	assert.Equal(t, "private_key_jwt", chatgpt.TokenEndpointAuthMethod)
	assert.Equal(t, "https://chatgpt.com/oauth/jwks.json", chatgpt.JSONWebKeysURI)
	assert.Equal(t, "RS256", chatgpt.TokenEndpointAuthSigningAlgorithm)

	vscode, err := cimd.ParseDocument(realClients["vscode"], testdata(t, "vscode"), defaults)
	require.NoError(t, err)
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, []string(vscode.GrantTypes))
	assert.Equal(t, []string{"http://127.0.0.1:33418/", "https://vscode.dev/redirect"}, []string(vscode.RedirectURIs))

	code, err := cimd.ParseDocument(realClients["claude-code"], testdata(t, "claude-code"), defaults)
	require.NoError(t, err)
	assert.Equal(t, []string{"http://localhost/callback", "http://127.0.0.1/callback"}, []string(code.RedirectURIs))
}

// doc builds a minimal valid public-client document for id, with overrides.
func doc(t *testing.T, id string, override map[string]any) []byte {
	t.Helper()
	m := map[string]any{
		"client_id":     id,
		"client_name":   "Test",
		"redirect_uris": []string{"https://app.example/cb"},
	}
	for k, v := range override {
		if v == nil {
			delete(m, k)
			continue
		}
		m[k] = v
	}
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return b
}

func TestParseDocumentDefaults(t *testing.T) {
	const id = "https://app.example/client.json"
	c, err := cimd.ParseDocument(id, doc(t, id, nil), defaults)
	require.NoError(t, err)
	assert.Equal(t, "none", c.TokenEndpointAuthMethod, "no auth method means none, never client_secret_basic")
	assert.Equal(t, []string{"authorization_code"}, []string(c.GrantTypes))
	assert.Equal(t, []string{"code"}, []string(c.ResponseTypes))

	c, err = cimd.ParseDocument(id, doc(t, id, map[string]any{
		"token_endpoint_auth_methods_supported": []string{"private_key_jwt", "none"},
		"jwks_uri":                              "https://app.example/jwks.json",
	}), defaults)
	require.NoError(t, err)
	assert.Equal(t, "private_key_jwt", c.TokenEndpointAuthMethod, "first allowed method of the plural list")

	c, err = cimd.ParseDocument(id, doc(t, id, map[string]any{
		"token_endpoint_auth_method": "private_key_jwt",
		"jwks":                       map[string]any{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0", "use": "sig", "kid": "k1"}}},
	}), defaults)
	require.NoError(t, err)
	require.NotNil(t, c.JSONWebKeys)
	assert.Len(t, c.JSONWebKeys.Keys, 1)
}

func TestParseDocumentRejects(t *testing.T) {
	const id = "https://app.example/client.json"
	for name, body := range map[string][]byte{
		"client_id mismatch":           doc(t, "https://app.example/other.json", nil),
		"client_secret":                doc(t, id, map[string]any{"client_secret": "s"}),
		"client_secret_expires_at":     doc(t, id, map[string]any{"client_secret_expires_at": 0}),
		"singular symmetric method":    doc(t, id, map[string]any{"token_endpoint_auth_method": "client_secret_basic"}),
		"plural with a symmetric":      doc(t, id, map[string]any{"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"}}),
		"singular client_secret_jwt":   doc(t, id, map[string]any{"token_endpoint_auth_method": "client_secret_jwt"}),
		"private_key_jwt without keys": doc(t, id, map[string]any{"token_endpoint_auth_method": "private_key_jwt"}),
		"private_key_jwt with both":    doc(t, id, map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://app.example/j", "jwks": map[string]any{"keys": []any{}}}),
		"http jwks_uri":                doc(t, id, map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "http://app.example/j"}),
		"jwks_uri with a port":         doc(t, id, map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://app.example:8443/j"}),
		"jwks_uri with user info":      doc(t, id, map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://u:p@app.example/j"}),
		"no redirect_uris":             doc(t, id, map[string]any{"redirect_uris": nil}),
		"empty redirect_uris":          doc(t, id, map[string]any{"redirect_uris": []string{}}),
		"only implicit grant":          doc(t, id, map[string]any{"grant_types": []string{"implicit"}}),
		"only token response":          doc(t, id, map[string]any{"response_types": []string{"token"}}),
		"unknown auth method only":     doc(t, id, map[string]any{"token_endpoint_auth_method": "tls_client_auth"}),
		"not an object":                []byte(`["client_id"]`),
		"not json":                     []byte(`client_id=x`),
		"over 5120 bytes":              doc(t, id, map[string]any{"client_name": strings.Repeat("a", cimd.MaxDocumentSize)}),
		"redirect with a fragment":     doc(t, id, map[string]any{"redirect_uris": []string{"https://app.example/cb#x"}}),
	} {
		_, err := cimd.ParseDocument(id, body, defaults)
		assert.ErrorIs(t, err, cimd.ErrInvalid, name)
	}
}

func TestParseDocumentClientIDExact(t *testing.T) {
	body := doc(t, "https://claude.ai/x", nil)
	_, err := cimd.ParseDocument("https://claude.ai/x", body, defaults)
	require.NoError(t, err)
	for _, fetchedAs := range []string{"https://Claude.ai/x", "https://claude.ai:443/x", "https://claude.ai/x/"} {
		_, err := cimd.ParseDocument(fetchedAs, body, defaults)
		assert.ErrorIs(t, err, cimd.ErrInvalid, fetchedAs)
	}
}

func TestParseDocumentScope(t *testing.T) {
	const id = "https://app.example/client.json"
	c, err := cimd.ParseDocument(id, doc(t, id, map[string]any{"scope": "read openid admin"}), defaults)
	require.NoError(t, err)
	assert.Equal(t, "read", c.Scope)

	c, err = cimd.ParseDocument(id, doc(t, id, nil), cimd.Defaults{Scope: []string{"openid", "offline_access", "read"}})
	require.NoError(t, err)
	assert.Equal(t, "offline_access read", c.Scope, "openid is never granted to a metadata-document client")
}

func TestParseDocumentNoGrantableScope(t *testing.T) {
	const id = "https://app.example/client.json"
	_, err := cimd.ParseDocument(id, doc(t, id, nil), cimd.Defaults{Scope: []string{"openid"}})
	assert.ErrorIs(t, err, cimd.ErrInvalid, "nothing left once openid is removed: refuse, never let the validator refill it")
}

func TestValidateClientIDURLASCIIOnly(t *testing.T) {
	issuer, _ := url.Parse("https://oauth2.example.com")
	for _, id := range []string{
		"https://clаude.ai/x", // Cyrillic a: renders as claude.ai
		"https://cl%D0%B0ude.ai/x",
		"https://claude.ai/a b",
		"https://claude.ai/a b",
		"https://claude.ai/a%00b",
	} {
		assert.ErrorIs(t, cimd.ValidateClientIDURL(id, issuer), cimd.ErrInvalid, "%q", id)
	}
	assert.NoError(t, cimd.ValidateClientIDURL("https://xn--clude-6ve.ai/x", issuer), "punycode stays visible as such")
}
