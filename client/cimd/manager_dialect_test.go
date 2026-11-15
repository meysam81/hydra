// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package cimd_test

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/client/cimd"
	"github.com/ory/hydra/v2/client/cimd/cimdtest"
	"github.com/ory/hydra/v2/internal/testhelpers"
)

// Two Hydra replicas resolving the same new client_id at once: one create
// wins, the other hits the unique index and must return the winner's row.
func TestManagerCreateConflictDialects(t *testing.T) {
	if testing.Short() {
		t.Skip("needs Docker databases")
	}
	for name, reg := range testhelpers.ConnectDatabases(t, true) {
		t.Run("db="+name, func(t *testing.T) {
			srv := cimdtest.NewServer(t)
			release := make(chan struct{})
			srv.Set(claudeID, cimdtest.Response{Header: cacheHeader, Block: release, Body: []byte(fmt.Sprintf(
				`{"client_id":%q,"redirect_uris":["https://claude.ai/cb"]}`, claudeID))})

			issuer, _ := url.Parse("https://oauth2.example.com")
			now := func() time.Time { return time.Now().UTC() }
			replica := func() *cimd.Manager {
				return cimd.NewManager(reg.Persister(), reg.ClientManager(), reg.ClientValidator(),
					&cimd.Fetcher{HTTP: cimdtest.Transport(srv.Server), MinTTL: 5 * time.Minute, MaxTTL: 24 * time.Hour},
					cimd.Defaults{Scope: []string{"read"}}, issuer, reg.Logger(), now)
			}
			a, b := replica(), replica()

			var wg sync.WaitGroup
			errs := make([]error, 2)
			for i, m := range []*cimd.Manager{a, b} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, errs[i] = m.GetClient(context.Background(), claudeID)
				}()
			}
			require.Eventually(t, func() bool { return srv.InFlight() == 2 }, 10*time.Second, 10*time.Millisecond)
			close(release)
			wg.Wait()
			for _, err := range errs {
				assert.NoError(t, err)
			}
			c, err := reg.ClientManager().GetConcreteClient(t.Context(), claudeID)
			require.NoError(t, err)
			assert.True(t, c.IsMetadataDocumentClient())
		})
	}
}
