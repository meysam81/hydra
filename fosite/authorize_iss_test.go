// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type issConfig struct {
	*Config
	iss string
}

func (c issConfig) GetAuthorizationResponseIssuer(context.Context) string { return c.iss }

func issRequest(mode ResponseModeType) *AuthorizeRequest {
	ar := NewAuthorizeRequest()
	ar.RedirectURI, _ = url.Parse("https://client.example/cb")
	ar.Client = &DefaultClient{RedirectURIs: []string{"https://client.example/cb"}}
	ar.ResponseMode = mode
	ar.State = "state-1234567890"
	return ar
}

func writeCode(t *testing.T, f *Fosite, mode ResponseModeType) *httptest.ResponseRecorder {
	t.Helper()
	resp := NewAuthorizeResponse()
	resp.AddParameter("code", "the-code")
	rw := httptest.NewRecorder()
	f.WriteAuthorizeResponse(context.Background(), rw, issRequest(mode), resp)
	return rw
}

func TestWriteAuthorizeResponseIss(t *testing.T) {
	on := &Fosite{Config: issConfig{Config: new(Config), iss: "https://op.example/"}}

	loc, err := url.Parse(writeCode(t, on, ResponseModeQuery).Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "https://op.example/", loc.Query().Get("iss"))
	assert.Equal(t, "the-code", loc.Query().Get("code"))

	loc, err = url.Parse(writeCode(t, on, ResponseModeFragment).Header().Get("Location"))
	require.NoError(t, err)
	frag, err := url.ParseQuery(loc.Fragment)
	require.NoError(t, err)
	assert.Equal(t, "https://op.example/", frag.Get("iss"))

	body := writeCode(t, on, ResponseModeFormPost).Body.String()
	assert.Contains(t, body, `name="iss"`)
	assert.Contains(t, body, "https://op.example/")

	for name, f := range map[string]*Fosite{
		"provider says off":  {Config: issConfig{Config: new(Config)}},
		"no provider at all": {Config: new(Config)},
	} {
		loc, err := url.Parse(writeCode(t, f, ResponseModeQuery).Header().Get("Location"))
		require.NoError(t, err)
		assert.False(t, loc.Query().Has("iss"), name)
	}
}

func TestWriteAuthorizeErrorIss(t *testing.T) {
	on := &Fosite{Config: issConfig{Config: new(Config), iss: "https://op.example/"}}

	rw := httptest.NewRecorder()
	on.WriteAuthorizeError(context.Background(), rw, issRequest(ResponseModeQuery), ErrInvalidScope)
	require.Equal(t, http.StatusSeeOther, rw.Code)
	loc, err := url.Parse(rw.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "https://op.example/", loc.Query().Get("iss"))
	assert.Equal(t, "invalid_scope", loc.Query().Get("error"))

	// No valid redirect: the error is written by Hydra, not sent to the client.
	ar := issRequest(ResponseModeQuery)
	ar.Client = nil
	rw = httptest.NewRecorder()
	on.WriteAuthorizeError(context.Background(), rw, ar, ErrInvalidClient)
	assert.Empty(t, rw.Header().Get("Location"))
	assert.False(t, strings.Contains(rw.Body.String(), "op.example"))

	off := &Fosite{Config: new(Config)}
	rw = httptest.NewRecorder()
	off.WriteAuthorizeError(context.Background(), rw, issRequest(ResponseModeQuery), ErrInvalidScope)
	loc, err = url.Parse(rw.Header().Get("Location"))
	require.NoError(t, err)
	assert.False(t, loc.Query().Has("iss"))
}
