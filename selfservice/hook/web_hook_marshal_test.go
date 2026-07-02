// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package hook

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/identity"
)

// TestTemplateContextMarshalJSON_AdminMetadata pins the fork behavior that lets the OIDC
// verified-email carrier reach the registration webhook: metadata_admin is included in
// ctx.identity only when the webhook opts in via includeAdminMetadata; credentials are never
// leaked into ctx.identity either way (Identity.MarshalJSON / WithAdminMetadataInJSON strip them).
func TestTemplateContextMarshalJSON_AdminMetadata(t *testing.T) {
	newCtx := func(includeAdminMetadata bool) templateContext {
		return templateContext{
			Identity: &identity.Identity{
				Traits:         identity.Traits(`{"email":"user@example.com"}`),
				MetadataPublic: []byte(`{"pub":"1"}`),
				MetadataAdmin:  []byte(`{"oidc_verified_email":"user@example.com"}`),
				Credentials: map[identity.CredentialsType]identity.Credentials{
					identity.CredentialsTypeOIDC: {
						Type:        identity.CredentialsTypeOIDC,
						Identifiers: []string{"google:123"},
						Config:      []byte(`{"secret":"do-not-leak"}`),
					},
				},
			},
			includeAdminMetadata: includeAdminMetadata,
		}
	}

	t.Run("metadata_admin is present when the webhook opts in", func(t *testing.T) {
		b, err := json.Marshal(newCtx(true))
		require.NoError(t, err)

		assert.Equal(t, "user@example.com",
			gjson.GetBytes(b, "identity.metadata_admin.oidc_verified_email").String())
		// non-admin fields still marshal normally
		assert.Equal(t, "user@example.com", gjson.GetBytes(b, "identity.traits.email").String())
		assert.Equal(t, "1", gjson.GetBytes(b, "identity.metadata_public.pub").String())
		// credentials must never leak into ctx.identity
		assert.False(t, gjson.GetBytes(b, "identity.credentials").Exists())
	})

	t.Run("metadata_admin is stripped by default", func(t *testing.T) {
		b, err := json.Marshal(newCtx(false))
		require.NoError(t, err)

		assert.False(t, gjson.GetBytes(b, "identity.metadata_admin").Exists())
		// everything else is unaffected — behavior identical to upstream marshaling
		assert.Equal(t, "user@example.com", gjson.GetBytes(b, "identity.traits.email").String())
		assert.Equal(t, "1", gjson.GetBytes(b, "identity.metadata_public.pub").String())
		assert.False(t, gjson.GetBytes(b, "identity.credentials").Exists())
	})
}
