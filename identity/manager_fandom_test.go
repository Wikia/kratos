// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package identity_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/x"
	"github.com/ory/x/configx"
)

func TestManagerFandomProtectedTraits(t *testing.T) {
	conf, reg := internal.NewFastRegistryWithMocks(t, configx.WithValues(map[string]interface{}{
		config.ViperKeyPublicBaseURL: "https://www.ory.sh/",
	}), configx.WithValues(testhelpers.DefaultIdentitySchemaConfig("file://./stub/manager.schema.json")))
	ctx, schemaID := testhelpers.WithAddIdentitySchema(context.Background(), t, conf, "file://./stub/protected.fandom.schema.json")

	// base traits for an identity; username must be unique as it is a credential identifier
	base := func(username, email string) map[string]interface{} {
		return map[string]interface{}{
			"username":      username,
			"email":         email,
			"backup_emails": []interface{}{"backup@fandom.com"},
			"contact":       map[string]interface{}{"phone": "123", "name": "name"},
			"unprotected":   "foo",
		}
	}
	marshal := func(t *testing.T, v map[string]interface{}) identity.Traits {
		b, err := json.Marshal(v)
		require.NoError(t, err)
		return b
	}
	create := func(t *testing.T, email string) (*identity.Identity, map[string]interface{}) {
		tr := base(x.NewUUID().String(), email)
		i := identity.NewIdentity(schemaID)
		i.Traits = marshal(t, tr)
		require.NoError(t, reg.IdentityManager().Create(ctx, i))
		return i, tr
	}

	t.Run("method=ProtectedTraitPaths", func(t *testing.T) {
		paths, err := reg.IdentityValidator().ProtectedTraitPaths(ctx, schemaID)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"email", "backup_emails", "contact.phone"}, paths)

		paths, err = reg.IdentityValidator().ProtectedTraitPaths(ctx, config.DefaultIdentityTraitsSchemaID)
		require.NoError(t, err)
		assert.Empty(t, paths)
	})

	t.Run("case=protected traits do not have to be unique", func(t *testing.T) {
		email := x.NewUUID().String() + "@fandom.com"
		create(t, email)
		create(t, email)
	})

	for _, tc := range []struct {
		name      string
		modify    func(tr map[string]interface{})
		protected bool
	}{
		{name: "no change", modify: func(tr map[string]interface{}) {}},
		{name: "unprotected trait", modify: func(tr map[string]interface{}) { tr["unprotected"] = "bar" }},
		{name: "unprotected nested trait", modify: func(tr map[string]interface{}) {
			tr["contact"] = map[string]interface{}{"phone": "123", "name": "other"}
		}},
		{name: "protected trait", modify: func(tr map[string]interface{}) { tr["email"] = "new@fandom.com" }, protected: true},
		{name: "removed protected trait", modify: func(tr map[string]interface{}) { delete(tr, "email") }, protected: true},
		{name: "protected array item", modify: func(tr map[string]interface{}) { tr["backup_emails"] = []interface{}{"other@fandom.com"} }, protected: true},
		{name: "added protected array item", modify: func(tr map[string]interface{}) {
			tr["backup_emails"] = []interface{}{"backup@fandom.com", "other@fandom.com"}
		}, protected: true},
		{name: "protected nested trait", modify: func(tr map[string]interface{}) {
			tr["contact"] = map[string]interface{}{"phone": "456", "name": "name"}
		}, protected: true},
	} {
		t.Run("case="+tc.name, func(t *testing.T) {
			t.Run("method=SetTraits", func(t *testing.T) {
				original, tr := create(t, "shared@fandom.com")
				tc.modify(tr)

				_, err := reg.IdentityManager().SetTraits(ctx, original.ID, marshal(t, tr))
				if tc.protected {
					require.Error(t, err)
					assert.Equal(t, identity.ErrProtectedFieldModified, errors.Cause(err))
				} else {
					require.NoError(t, err)
				}

				updated, err := reg.IdentityManager().SetTraits(ctx, original.ID, marshal(t, tr), identity.ManagerAllowWriteProtectedTraits)
				require.NoError(t, err)
				assert.JSONEq(t, string(marshal(t, tr)), string(updated.Traits))
			})

			t.Run("method=Update", func(t *testing.T) {
				original, tr := create(t, "shared@fandom.com")
				before := marshal(t, tr)
				tc.modify(tr)

				original.Traits = marshal(t, tr)
				err := reg.IdentityManager().Update(ctx, original)

				fromStore, getErr := reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, original.ID)
				require.NoError(t, getErr)
				if tc.protected {
					require.Error(t, err)
					assert.Equal(t, identity.ErrProtectedFieldModified, errors.Cause(err))
					assert.JSONEq(t, string(before), string(fromStore.Traits))
				} else {
					require.NoError(t, err)
					assert.JSONEq(t, string(marshal(t, tr)), string(fromStore.Traits))
				}
			})
		})
	}
}
