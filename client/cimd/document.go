// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Package cimd resolves OAuth Client ID Metadata Documents
// (draft-ietf-oauth-client-id-metadata-document-03): a client_id that is an
// https URL names a JSON document describing the client. Resolved clients are
// stored as ordinary hydra_client rows marked with client.MetadataDocumentKey.
package cimd

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/pkg/errors"

	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/x"
	"github.com/ory/x/sqlxx"
)

// MaxDocumentSize is the most of a metadata document that is read (§10.11).
const MaxDocumentSize = 5120

// maxClientIDLength is hydra_client.id's column width.
const maxClientIDLength = 255

// ErrInvalid wraps every reason a client_id URL or a document is refused.
var ErrInvalid = errors.New("cimd: invalid client metadata document")

func invalid(format string, args ...any) error {
	return errors.Wrapf(ErrInvalid, format, args...)
}

// IsClientIDURL reports whether id is meant as a metadata document URL. Hydra
// gives dynamically registered clients UUIDs, so only admin-created clients
// could otherwise start with https://.
func IsClientIDURL(id string) bool { return strings.HasPrefix(id, "https://") }

// ValidateClientIDURL applies §3, stricter where the draft only discourages:
// no query, and no port (Hydra's egress reaches 443 only). The id is never
// normalised; issuer is refused as a client host (§10.1).
func ValidateClientIDURL(id string, issuer *url.URL) error {
	if len(id) > maxClientIDLength {
		return invalid("client_id is longer than %d bytes", maxClientIDLength)
	}
	if !IsClientIDURL(id) {
		return invalid("client_id is not an https URL")
	}
	// Printable ASCII only: the consent page names the host, and a look-alike
	// (Cyrillic "а" in claude.ai) must show as punycode, not as claude.ai.
	if strings.IndexFunc(id, func(r rune) bool { return r <= ' ' || r > '~' }) >= 0 {
		return invalid("client_id is not printable ASCII")
	}
	u, err := url.Parse(id)
	switch {
	case err != nil:
		return invalid("client_id does not parse")
	case u.Hostname() == "":
		return invalid("client_id has no host")
	case u.User != nil:
		return invalid("client_id carries user info")
	case u.Port() != "" || strings.HasSuffix(u.Host, ":"):
		return invalid("client_id names a port")
	case u.Fragment != "" || strings.Contains(id, "#"):
		return invalid("client_id has a fragment")
	case u.RawQuery != "" || u.ForceQuery:
		return invalid("client_id has a query")
	case u.EscapedPath() == "" || u.EscapedPath() == "/":
		return invalid("client_id has no path")
	case issuer != nil && strings.EqualFold(u.Hostname(), issuer.Hostname()):
		return invalid("client_id is on the issuer's host")
	}
	if strings.IndexFunc(u.Hostname(), func(r rune) bool { return r <= ' ' || r > '~' }) >= 0 {
		return invalid("client_id host is not printable ASCII")
	}
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		dec, err := url.PathUnescape(seg)
		if err != nil || dec == "." || dec == ".." {
			return invalid("client_id path has a dot segment")
		}
		if strings.IndexFunc(dec, func(r rune) bool { return r < ' ' || r == 0x7f }) >= 0 {
			return invalid("client_id path has a control character")
		}
	}
	return nil
}

// Defaults are what a document inherits when it says nothing.
type Defaults struct {
	// Scope is oidc.dynamic_client_registration.default_scope.
	Scope []string
}

var (
	allowedGrantTypes    = []string{"authorization_code", "refresh_token"}
	allowedResponseTypes = []string{"code"}
	// Asymmetric methods Hydra verifies. Everything else is refused when it is
	// the only choice; a shared-secret method anywhere refuses the document.
	allowedAuthMethods   = []string{"none", "private_key_jwt"}
	symmetricAuthMethods = []string{"client_secret_basic", "client_secret_post", "client_secret_jwt"}
)

type document struct {
	ClientID                    string          `json:"client_id"`
	ClientName                  string          `json:"client_name"`
	ClientURI                   string          `json:"client_uri"`
	RedirectURIs                []string        `json:"redirect_uris"`
	GrantTypes                  []string        `json:"grant_types"`
	ResponseTypes               []string        `json:"response_types"`
	Scope                       string          `json:"scope"`
	TokenEndpointAuthMethod     string          `json:"token_endpoint_auth_method"`
	TokenEndpointAuthMethods    []string        `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlg string          `json:"token_endpoint_auth_signing_alg"`
	JWKSURI                     string          `json:"jwks_uri"`
	JWKS                        json.RawMessage `json:"jwks"`
}

// ParseDocument validates body as the metadata document fetched from id and
// returns the client it describes (§4, §5, §6). Only the fields Hydra needs
// for the code flow are kept; logo, logout, sector and request-object
// metadata are dropped. The result has no Metadata: the caller marks it.
func ParseDocument(id string, body []byte, d Defaults) (*client.Client, error) {
	if len(body) > MaxDocumentSize {
		return nil, invalid("document is larger than %d bytes", MaxDocumentSize)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(body, &keys); err != nil {
		return nil, invalid("document is not a JSON object")
	}
	var doc document
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, invalid("document has a field of the wrong type")
	}
	if doc.ClientID != id {
		return nil, invalid("document client_id does not match the URL it was fetched from")
	}
	for _, k := range []string{"client_secret", "client_secret_expires_at"} {
		if _, ok := keys[k]; ok {
			return nil, invalid("document carries %s", k)
		}
	}

	method, err := authMethod(doc)
	if err != nil {
		return nil, err
	}

	c := &client.Client{
		ID:                      id,
		Name:                    doc.ClientName,
		TokenEndpointAuthMethod: method,
		SkipConsent:             false,
	}
	if u, err := url.Parse(doc.ClientURI); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
		c.ClientURI = doc.ClientURI
	}

	if len(doc.RedirectURIs) == 0 {
		return nil, invalid("document has no redirect_uris")
	}
	for _, r := range doc.RedirectURIs {
		if u, err := url.Parse(r); err != nil || u.Scheme == "" || u.Fragment != "" || strings.Contains(r, "#") {
			return nil, invalid("redirect_uri %q is not an absolute URI without a fragment", r)
		}
	}
	c.RedirectURIs = sqlxx.StringSliceJSONFormat(doc.RedirectURIs)

	grants := []string{"authorization_code"}
	if _, ok := keys["grant_types"]; ok {
		grants = intersect(doc.GrantTypes, allowedGrantTypes)
	}
	if len(grants) == 0 {
		return nil, invalid("document grants nothing Hydra supports for it")
	}
	c.GrantTypes = sqlxx.StringSliceJSONFormat(grants)

	responses := []string{"code"}
	if _, ok := keys["response_types"]; ok {
		responses = intersect(doc.ResponseTypes, allowedResponseTypes)
	}
	if len(responses) == 0 {
		return nil, invalid("document has no supported response_types")
	}
	c.ResponseTypes = sqlxx.StringSliceJSONFormat(responses)

	// openid is never granted: fosite parses request objects before it checks
	// scope, and the stored scope is what then refuses them.
	allowed := slices.DeleteFunc(slices.Clone(d.Scope), func(s string) bool { return s == "openid" })
	if len(allowed) == 0 {
		// An empty scope would be refilled by Hydra's validator from the
		// default, openid included.
		return nil, invalid("no scope is grantable to a metadata-document client")
	}
	scope := allowed
	if strings.TrimSpace(doc.Scope) != "" {
		scope = intersect(strings.Fields(doc.Scope), allowed)
		if len(scope) == 0 {
			return nil, invalid("document asks for no scope Hydra grants it")
		}
	}
	c.Scope = strings.Join(scope, " ")

	if method == "private_key_jwt" {
		if err := keySet(c, doc); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// authMethod picks the token endpoint method: the singular field, else the
// first allowed entry of the plural list, else none (§5, never RFC 7591's
// client_secret_basic default).
func authMethod(doc document) (string, error) {
	for _, m := range append([]string{doc.TokenEndpointAuthMethod}, doc.TokenEndpointAuthMethods...) {
		if slices.Contains(symmetricAuthMethods, m) {
			return "", invalid("document allows the shared-secret method %s", m)
		}
	}
	if doc.TokenEndpointAuthMethod != "" {
		if !slices.Contains(allowedAuthMethods, doc.TokenEndpointAuthMethod) {
			return "", invalid("token_endpoint_auth_method %s is not supported", doc.TokenEndpointAuthMethod)
		}
		return doc.TokenEndpointAuthMethod, nil
	}
	if len(doc.TokenEndpointAuthMethods) > 0 {
		for _, m := range doc.TokenEndpointAuthMethods {
			if slices.Contains(allowedAuthMethods, m) {
				return m, nil
			}
		}
		return "", invalid("no supported token endpoint auth method")
	}
	return "none", nil
}

// keySet stores the client's public keys for private_key_jwt: exactly one of
// jwks and an https jwks_uri.
func keySet(c *client.Client, doc document) error {
	hasJWKS := len(doc.JWKS) > 0 && string(doc.JWKS) != "null"
	switch {
	case hasJWKS == (doc.JWKSURI != ""):
		return invalid("private_key_jwt needs exactly one of jwks and jwks_uri")
	case doc.JWKSURI != "":
		u, err := url.Parse(doc.JWKSURI)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
			return invalid("jwks_uri is not an https URL")
		}
		c.JSONWebKeysURI = doc.JWKSURI
	default:
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(doc.JWKS, &set); err != nil || len(set.Keys) == 0 {
			return invalid("jwks is not a non-empty key set")
		}
		for _, k := range set.Keys {
			if !k.IsPublic() {
				return invalid("jwks carries private key material")
			}
		}
		c.JSONWebKeys = &x.JoseJSONWebKeySet{JSONWebKeySet: &set}
	}
	c.TokenEndpointAuthSigningAlgorithm = doc.TokenEndpointAuthSigningAlg
	return nil
}

// intersect keeps the entries of have that are in allowed, in have's order,
// once each.
func intersect(have, allowed []string) []string {
	var out []string
	for _, v := range have {
		if slices.Contains(allowed, v) && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}
