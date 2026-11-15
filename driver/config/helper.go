// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"net/url"

	"github.com/pkg/errors"

	"github.com/ory/x/logrusx"
)

func Validate(ctx context.Context, l *logrusx.Logger, p *DefaultProvider) error {
	if p.IssuerURL(ctx).String() == "" && !p.IsDevelopmentMode(ctx) {
		l.Errorf("Configuration key `%s` must be set `dev` is `false`. To find out more, use `hydra help serve`.", KeyIssuerURL)
		return errors.New("issuer URL must be set unless development mode is enabled")
	}

	if p.IssuerURL(ctx).Scheme != "https" && !p.IsDevelopmentMode(ctx) {
		l.Errorf("Scheme from configuration key `%s` must be `https` when `dev` is `false`. Got scheme in value `%s` is `%s`. To find out more, use `hydra help serve`.", KeyIssuerURL, p.IssuerURL(ctx).String(), p.IssuerURL(ctx).Scheme)
		return errors.New("issuer URL scheme must be HTTPS unless development mode is enabled")
	}

	// Hydra fetches metadata documents and their jwks_uri for anyone who asks:
	// the private-range guard must hold for every client URL, without holes.
	if p.CIMDEnabled(ctx) {
		if !p.ClientHTTPNoPrivateIPRanges() {
			return errors.Errorf("%s requires %s to be true", KeyCIMDEnabled, KeyClientHTTPNoPrivateIPRanges)
		}
		if len(p.ClientHTTPPrivateIPExceptionURLs()) > 0 {
			return errors.Errorf("%s requires %s to be empty", KeyCIMDEnabled, KeyClientHTTPPrivateIPExceptionURLs)
		}
	}

	return nil
}

func urlRoot(u *url.URL) *url.URL {
	if u.Path == "" {
		u.Path = "/"
	}
	return u
}
