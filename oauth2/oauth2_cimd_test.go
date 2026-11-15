// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	hydra "github.com/ory/hydra-client-go/v2"
	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/client/cimd/cimdtest"
	"github.com/ory/hydra/v2/driver"
	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/x/configx"
)

const (
	claudeCodeID   = "https://claude.ai/oauth/claude-code-client-metadata"
	chatgptLikeID  = "https://chatgpt.example/oauth/client.json"
	loopbackReturn = "http://localhost:53111/callback"
)

// cimdEnv is a Hydra with its public and admin APIs, a login/consent UI that
// accepts everything, and a server for metadata documents.
type cimdEnv struct {
	reg           *driver.RegistrySQL
	public, admin *httptest.Server
	docs          *cimdtest.Server
	adminAPI      *hydra.APIClient
	logins        atomic.Int32
}

func newCIMDEnv(t *testing.T, dsn string, migrate, enabled bool, docs *cimdtest.Server, overrides ...map[string]any) *cimdEnv {
	t.Helper()
	if docs == nil {
		docs = cimdtest.NewServer(t)
	}
	values := map[string]any{
		config.KeyClientHTTPNoPrivateIPRanges: true,
		config.KeyCIMDEnabled:                 enabled,
		config.KeyCIMDMinTTL:                  "1s",
		config.KeyDefaultClientScope:          []string{"offline_access", "read"},
	}
	for _, o := range overrides {
		for k, v := range o {
			values[k] = v
		}
	}
	opts := []driver.OptionsModifier{
		driver.WithConfigOptions(configx.WithValues(values)),
		driver.WithCIMDHTTPClient(cimdtest.Transport(docs.Server)),
	}
	var reg *driver.RegistrySQL
	if dsn == "" {
		reg = testhelpers.NewRegistryMemory(t, opts...)
	} else {
		reg = testhelpers.NewRegistrySQLFromURL(t, dsn, migrate, true, opts...)
	}
	e := &cimdEnv{reg: reg, docs: docs}
	ctx := context.Background()
	e.public, e.admin = testhelpers.NewOAuth2Server(ctx, t, reg)
	reg.Config().MustSet(ctx, config.KeyRefreshTokenLifespan, time.Hour)
	e.adminAPI = hydra.NewAPIClient(hydra.NewConfiguration())
	e.adminAPI.GetConfig().Servers = hydra.ServerConfigurations{{URL: e.admin.URL}}

	testhelpers.NewLoginConsentUI(t, reg.Config(),
		func(w http.ResponseWriter, r *http.Request) {
			e.logins.Add(1)
			v, _, err := e.adminAPI.OAuth2API.AcceptOAuth2LoginRequest(context.Background()).
				LoginChallenge(r.URL.Query().Get("login_challenge")).
				AcceptOAuth2LoginRequest(hydra.AcceptOAuth2LoginRequest{Subject: "alice"}).Execute()
			require.NoError(t, err)
			http.Redirect(w, r, v.RedirectTo, http.StatusFound)
		},
		func(w http.ResponseWriter, r *http.Request) {
			challenge := r.URL.Query().Get("consent_challenge")
			cr, _, err := e.adminAPI.OAuth2API.GetOAuth2ConsentRequest(context.Background()).ConsentChallenge(challenge).Execute()
			require.NoError(t, err)
			v, _, err := e.adminAPI.OAuth2API.AcceptOAuth2ConsentRequest(context.Background()).
				ConsentChallenge(challenge).
				AcceptOAuth2ConsentRequest(hydra.AcceptOAuth2ConsentRequest{GrantScope: cr.RequestedScope}).Execute()
			require.NoError(t, err)
			http.Redirect(w, r, v.RedirectTo, http.StatusFound)
		})
	return e
}

func (e *cimdEnv) serve(id string, doc map[string]any) {
	doc["client_id"] = id
	b, _ := json.Marshal(doc)
	e.docs.Set(id, cimdtest.Response{Header: http.Header{"Cache-Control": []string{"max-age=1"}}, Body: b})
}

type pkce struct{ verifier, challenge string }

func newPKCE() pkce {
	v := strings.ReplaceAll(uuid.Must(uuid.NewV4()).String()+uuid.Must(uuid.NewV4()).String(), "-", "")
	sum := sha256.Sum256([]byte(v))
	return pkce{verifier: v, challenge: base64.RawURLEncoding.EncodeToString(sum[:])}
}

// authorize runs the browser leg until Hydra sends it to a host that is
// neither Hydra nor the login/consent UI, and returns that location.
func (e *cimdEnv) authorize(t *testing.T, method string, q url.Values) *url.URL {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	ours := map[string]bool{}
	for _, raw := range []string{e.public.URL, e.reg.Config().LoginURL(context.Background()).String(), e.reg.Config().ConsentURL(context.Background()).String()} {
		u, _ := url.Parse(raw)
		ours[u.Host] = true
	}
	hc := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if !ours[req.URL.Host] {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	var res *http.Response
	var err error
	if method == http.MethodPost {
		res, err = hc.PostForm(e.public.URL+"/oauth2/auth", q)
	} else {
		res, err = hc.Get(e.public.URL + "/oauth2/auth?" + q.Encode())
	}
	require.NoError(t, err)
	defer res.Body.Close() //nolint:errcheck
	loc := res.Header.Get("Location")
	if loc == "" {
		return res.Request.URL
	}
	u, err := url.Parse(loc)
	require.NoError(t, err)
	return u
}

func authorizeParams(clientID, redirect, scope string, p pkce) url.Values {
	return url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"response_type":         {"code"},
		"scope":                 {scope},
		"state":                 {"state-" + uuid.Must(uuid.NewV4()).String()},
		"code_challenge":        {p.challenge},
		"code_challenge_method": {"S256"},
	}
}

func (e *cimdEnv) token(t *testing.T, form url.Values) (int, gjson.Result) {
	t.Helper()
	res, err := http.PostForm(e.public.URL+"/oauth2/token", form)
	require.NoError(t, err)
	defer res.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, gjson.ParseBytes(body)
}

func (e *cimdEnv) codeFlow(t *testing.T, clientID, redirect string, extra url.Values) gjson.Result {
	t.Helper()
	p := newPKCE()
	loc := e.authorize(t, http.MethodGet, authorizeParams(clientID, redirect, "offline_access read", p))
	code := loc.Query().Get("code")
	require.NotEmpty(t, code, "callback: %s", loc)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "client_id": {clientID}, "code_verifier": {p.verifier}}
	for k, v := range extra {
		form[k] = v
	}
	status, tok := e.token(t, form)
	require.Equal(t, http.StatusOK, status, tok.Raw)
	return tok
}

func TestCIMDPublicClientFlow(t *testing.T) {
	e := newCIMDEnv(t, "", true, true, nil)
	e.serve(claudeCodeID, map[string]any{
		"client_name": "Claude Code", "redirect_uris": []string{"http://localhost/callback", "http://127.0.0.1/callback"},
		"grant_types": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_method": "none",
	})

	p := newPKCE()
	loc := e.authorize(t, http.MethodGet, authorizeParams(claudeCodeID, loopbackReturn, "offline_access read", p))
	require.Equal(t, "localhost:53111", loc.Host, "port-agnostic localhost redirect: %s", loc)
	code := loc.Query().Get("code")
	require.NotEmpty(t, code)
	disco := gjson.GetBytes(func() []byte {
		res, err := http.Get(e.public.URL + "/.well-known/oauth-authorization-server")
		require.NoError(t, err)
		defer res.Body.Close() //nolint:errcheck
		b, _ := io.ReadAll(res.Body)
		return b
	}(), "issuer").String()
	assert.Equal(t, disco, loc.Query().Get("iss"), "RFC 9207 iss equals the discovery issuer")

	status, tok := e.token(t, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {loopbackReturn}, "client_id": {claudeCodeID}, "code_verifier": {p.verifier}})
	require.Equal(t, http.StatusOK, status, tok.Raw)
	require.NotEmpty(t, tok.Get("refresh_token").String())

	intro := testhelpers.IntrospectToken(t, tok.Get("access_token").String(), e.admin)
	assert.True(t, intro.Get("active").Bool())
	assert.Equal(t, claudeCodeID, intro.Get("client_id").String())

	status, refreshed := e.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.Get("refresh_token").String()}, "client_id": {claudeCodeID}})
	require.Equal(t, http.StatusOK, status, refreshed.Raw)
}

// clientKey is the test RSA key of a private_key_jwt client and its public set.
func clientKey(t *testing.T) (*rsa.PrivateKey, map[string]any) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub, err := json.Marshal(jose.JSONWebKey{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"})
	require.NoError(t, err)
	var jwk map[string]any
	require.NoError(t, json.Unmarshal(pub, &jwk))
	return key, map[string]any{"keys": []any{jwk}}
}

func signJWT(t *testing.T, key *rsa.PrivateKey, alg jose.SignatureAlgorithm, claims any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	require.NoError(t, err)
	s, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)
	return s
}

func (e *cimdEnv) assertion(t *testing.T, key *rsa.PrivateKey) url.Values {
	now := time.Now()
	return url.Values{
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion": {signJWT(t, key, jose.RS256, jwt.Claims{
			Issuer: chatgptLikeID, Subject: chatgptLikeID, Audience: jwt.Audience{e.public.URL + "/oauth2/token"},
			ID: uuid.Must(uuid.NewV4()).String(), IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		})},
	}
}

func TestCIMDPrivateKeyJWTFlow(t *testing.T) {
	e := newCIMDEnv(t, "", true, true, nil)
	key, jwks := clientKey(t)
	e.serve(chatgptLikeID, map[string]any{
		"client_name": "ChatGPT-like", "redirect_uris": []string{"https://chatgpt.example/cb"},
		"grant_types": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "RS256", "jwks": jwks,
	})

	tok := e.codeFlow(t, chatgptLikeID, "https://chatgpt.example/cb", e.assertion(t, key))
	assert.NotEmpty(t, tok.Get("access_token").String())

	p := newPKCE()
	loc := e.authorize(t, http.MethodGet, authorizeParams(chatgptLikeID, "https://chatgpt.example/cb", "offline_access read", p))
	status, body := e.token(t, url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "redirect_uri": {"https://chatgpt.example/cb"}, "client_id": {chatgptLikeID}, "code_verifier": {p.verifier}})
	assert.Equal(t, http.StatusUnauthorized, status, body.Raw)
	assert.Equal(t, "invalid_client", body.Get("error").String())
}

// A private_key_jwt client whose keys are at a jwks_uri, fetched with the
// document client while CIMD is on.
func TestCIMDPrivateKeyJWTWithJWKSURI(t *testing.T) {
	const jwksURL = "https://chatgpt.example/oauth/jwks.json"
	serveClient := func(e *cimdEnv) {
		e.serve(chatgptLikeID, map[string]any{
			"redirect_uris": []string{"https://chatgpt.example/cb"}, "grant_types": []string{"authorization_code", "refresh_token"},
			"token_endpoint_auth_method": "private_key_jwt", "token_endpoint_auth_signing_alg": "RS256", "jwks_uri": jwksURL,
		})
	}

	t.Run("ok", func(t *testing.T) {
		e := newCIMDEnv(t, "", true, true, nil)
		key, jwks := clientKey(t)
		serveClient(e)
		body, _ := json.Marshal(jwks)
		e.docs.Set(jwksURL, cimdtest.Response{Body: body})
		tok := e.codeFlow(t, chatgptLikeID, "https://chatgpt.example/cb", e.assertion(t, key))
		assert.NotEmpty(t, tok.Get("access_token").String())
	})

	t.Run("redirect", func(t *testing.T) {
		e := newCIMDEnv(t, "", true, true, nil)
		key, jwks := clientKey(t)
		serveClient(e)
		const target = "https://chatgpt.example/oauth/real-jwks.json"
		body, _ := json.Marshal(jwks)
		e.docs.Set(jwksURL, cimdtest.Response{Status: http.StatusFound, Header: http.Header{"Location": []string{target}}})
		e.docs.Set(target, cimdtest.Response{Body: body})

		p := newPKCE()
		loc := e.authorize(t, http.MethodGet, authorizeParams(chatgptLikeID, "https://chatgpt.example/cb", "offline_access read", p))
		form := url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "redirect_uri": {"https://chatgpt.example/cb"}, "client_id": {chatgptLikeID}, "code_verifier": {p.verifier}}
		for k, v := range e.assertion(t, key) {
			form[k] = v
		}
		status, res := e.token(t, form)
		assert.NotEqual(t, http.StatusOK, status, res.Raw)
		assert.Zero(t, e.docs.Hits(target), "the redirect is never followed")
	})
}

func TestCIMDRefusesRequestObjects(t *testing.T) {
	// Even when the DCR default scope grants openid, a metadata-document
	// client never gets it, so fosite refuses every request object.
	e := newCIMDEnv(t, "", true, true, nil, map[string]any{config.KeyDefaultClientScope: []string{"openid", "offline_access", "read"}})
	key, jwks := clientKey(t)
	e.serve(chatgptLikeID, map[string]any{
		"redirect_uris":              []string{"https://chatgpt.example/cb", "https://chatgpt.example/other"},
		"token_endpoint_auth_method": "private_key_jwt", "jwks": jwks,
	})
	override := map[string]any{"redirect_uri": "https://chatgpt.example/other", "client_id": chatgptLikeID, "iss": chatgptLikeID, "aud": e.public.URL, "scope": "openid read"}
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(override)
	objects := map[string]string{
		"signed":   signJWT(t, key, jose.RS256, override),
		"alg none": none + "." + base64.RawURLEncoding.EncodeToString(payload) + ".",
	}
	for name, obj := range objects {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			q := authorizeParams(chatgptLikeID, "https://chatgpt.example/cb", "openid read", newPKCE())
			q.Set("request", obj)
			loc := e.authorize(t, method, q)
			assert.Empty(t, loc.Query().Get("code"), "%s %s: %s", name, method, loc)
			assert.Equal(t, "invalid_scope", loc.Query().Get("error"), "%s %s: %s", name, method, loc)
		}
	}
	assert.Zero(t, e.logins.Load(), "no login request was ever created")
}

func TestCIMDDocumentChangesMidFlow(t *testing.T) {
	e := newCIMDEnv(t, "", true, true, nil)
	doc := map[string]any{"redirect_uris": []string{"https://app.example/one", "https://app.example/two"}, "grant_types": []string{"authorization_code", "refresh_token"}}
	const id = "https://app.example/client.json"
	e.serve(id, doc)

	p := newPKCE()
	loc := e.authorize(t, http.MethodGet, authorizeParams(id, "https://app.example/one", "offline_access read", p))
	code := loc.Query().Get("code")
	require.NotEmpty(t, code)

	e.serve(id, map[string]any{"redirect_uris": []string{"https://app.example/two"}, "grant_types": []string{"authorization_code", "refresh_token"}})
	time.Sleep(1100 * time.Millisecond) // past the 1 s cache floor

	status, tok := e.token(t, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://app.example/one"}, "client_id": {id}, "code_verifier": {p.verifier}})
	require.Equal(t, http.StatusOK, status, tok.Raw)

	loc = e.authorize(t, http.MethodGet, authorizeParams(id, "https://app.example/one", "offline_access read", newPKCE()))
	assert.Empty(t, loc.Query().Get("code"), "the removed redirect is refused for new flows: %s", loc)
}

func TestCIMDDisabledKeepsExistingGrants(t *testing.T) {
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "hydra.sqlite") + "?_fk=true&mode=rwc"
	docs := cimdtest.NewServer(t)
	on := newCIMDEnv(t, dsn, true, true, docs)
	on.serve(claudeCodeID, map[string]any{"redirect_uris": []string{"http://localhost/callback"}, "grant_types": []string{"authorization_code", "refresh_token"}})
	tok := on.codeFlow(t, claudeCodeID, loopbackReturn, nil)
	hits := docs.Hits(claudeCodeID)

	off := newCIMDEnv(t, dsn, false, false, docs)
	status, refreshed := off.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.Get("refresh_token").String()}, "client_id": {claudeCodeID}})
	require.Equal(t, http.StatusOK, status, refreshed.Raw)

	res, err := http.Get(off.public.URL + "/.well-known/oauth-authorization-server")
	require.NoError(t, err)
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	assert.False(t, gjson.GetBytes(b, "client_id_metadata_document_supported").Exists())

	const unknown = "https://unknown.example/client.json"
	off.serve(unknown, map[string]any{"redirect_uris": []string{"https://unknown.example/cb"}})
	loc := off.authorize(t, http.MethodGet, authorizeParams(unknown, "https://unknown.example/cb", "read", newPKCE()))
	assert.Empty(t, loc.Query().Get("code"))
	assert.Zero(t, docs.Hits(unknown), "switch off: nothing is fetched")
	assert.Equal(t, hits, docs.Hits(claudeCodeID), "switch off: the stored row is served as is")
}

func TestCIMDDisabledIsUpstream(t *testing.T) {
	e := newCIMDEnv(t, "", true, false, nil)
	id := uuid.Must(uuid.NewV4()).String()
	require.NoError(t, e.reg.ClientManager().CreateClient(context.Background(), &client.Client{
		ID: id, TokenEndpointAuthMethod: "none", RedirectURIs: []string{"https://app.example/cb"},
		GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}, Scope: "offline_access read",
	}))
	loc := e.authorize(t, http.MethodGet, authorizeParams(id, "https://app.example/cb", "read", newPKCE()))
	require.NotEmpty(t, loc.Query().Get("code"), loc.String())
	assert.False(t, loc.Query().Has("iss"), "no iss while CIMD is off")

	e.serve(claudeCodeID, map[string]any{"redirect_uris": []string{"http://localhost/callback"}})
	loc = e.authorize(t, http.MethodGet, authorizeParams(claudeCodeID, loopbackReturn, "read", newPKCE()))
	assert.Empty(t, loc.Query().Get("code"))
	assert.Zero(t, e.docs.Hits(claudeCodeID))
}
