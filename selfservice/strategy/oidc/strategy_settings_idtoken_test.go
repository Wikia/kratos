// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc_test

// Fandom-start [SPLAT-1086]: linking a provider with the native SDK's id_token on an API settings flow

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/x/sqlxx"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/strategy/oidc"
	"github.com/ory/kratos/x"
)

func TestSettingsStrategyLinkWithIDToken(t *testing.T) {
	ctx := context.Background()
	conf, reg := internal.NewFastRegistryWithMocks(t)
	_ = newUI(t, reg)
	_ = testhelpers.NewErrorTestServer(t, reg)
	publicTS, adminTS := testhelpers.NewKratosServers(t)

	const providerID = "test-provider"
	viperSetProviderConfig(t, conf, oidc.Configuration{
		Provider:     providerID,
		ID:           providerID,
		ClientID:     "client",
		ClientSecret: "secret",
		IssuerURL:    "https://issuer.example.com/",
		Mapper:       "file://./stub/oidc.facebook.jsonnet",
	})
	oidc.RegisterTestProvider(t, providerID)
	testhelpers.InitKratosServers(t, reg, publicTS, adminTS)
	testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/settings.schema.json")

	newPasswordIdentity := func(t *testing.T) *identity.Identity {
		email := x.NewUUID().String() + "@example.org"
		i := &identity.Identity{
			ID:       x.NewUUID(),
			SchemaID: config.DefaultIdentityTraitsSchemaID,
			Traits:   identity.Traits(`{"email":"` + email + `"}`),
			State:    identity.StateActive,
			Credentials: map[identity.CredentialsType]identity.Credentials{
				identity.CredentialsTypePassword: {
					Type:        identity.CredentialsTypePassword,
					Identifiers: []string{email},
					Config:      sqlxx.JSONRawMessage(`{"hashed_password":"$argon2id$iammocked...."}`),
				},
			},
		}
		require.NoError(t, reg.PrivilegedIdentityPool().CreateIdentity(ctx, i))
		return i
	}

	// idToken builds a stub token the test provider accepts as claims (see TestProvider.Verify).
	idToken := func(subject, nonce string) string {
		return `{"iss":"https://issuer.example.com/","sub":"` + subject + `","nonce":"` + nonce + `"}`
	}

	submitLink := func(t *testing.T, client *http.Client, values url.Values) (*http.Response, []byte) {
		f := testhelpers.InitializeSettingsFlowViaAPI(t, client, publicTS)
		values.Set("method", "oidc")
		values.Set("link", providerID)
		req, err := http.NewRequest(http.MethodPost, f.Ui.Action, strings.NewReader(values.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		res, err := client.Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		return res, body
	}

	linkedSubjects := func(t *testing.T, id uuid.UUID) []string {
		actual, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, id)
		require.NoError(t, err)
		var cc identity.CredentialsOIDC
		if _, err := actual.ParseCredentials(identity.CredentialsTypeOIDC, &cc); err != nil {
			return nil
		}
		var subjects []string
		for _, p := range cc.Providers {
			if p.Provider == providerID {
				subjects = append(subjects, p.Subject)
			}
		}
		return subjects
	}

	t.Run("case=valid id_token links the subject to the session identity", func(t *testing.T) {
		i := newPasswordIdentity(t)
		client := testhelpers.NewHTTPClientWithIdentitySessionToken(t, ctx, reg, i)
		subject, nonce := x.NewUUID().String(), x.NewUUID().String()

		res, body := submitLink(t, client, url.Values{"id_token": {idToken(subject, nonce)}, "id_token_nonce": {nonce}})

		assert.Equal(t, http.StatusOK, res.StatusCode, "%s", body)
		assert.EqualValues(t, flow.StateSuccess, gjson.GetBytes(body, "state").String(), "%s", body)
		assert.Equal(t, []string{subject}, linkedSubjects(t, i.ID))
	})

	t.Run("case=invalid id_token is rejected and nothing is linked", func(t *testing.T) {
		i := newPasswordIdentity(t)
		client := testhelpers.NewHTTPClientWithIdentitySessionToken(t, ctx, reg, i)

		_, body := submitLink(t, client, url.Values{"id_token": {"error"}})

		assert.Equal(t, "Could not verify id_token", gjson.GetBytes(body, "error.reason").String(), "%s", body)
		assert.Empty(t, linkedSubjects(t, i.ID))
	})

	t.Run("case=nonce mismatch is rejected and nothing is linked", func(t *testing.T) {
		i := newPasswordIdentity(t)
		client := testhelpers.NewHTTPClientWithIdentitySessionToken(t, ctx, reg, i)
		subject := x.NewUUID().String()

		_, body := submitLink(t, client, url.Values{"id_token": {idToken(subject, "token-nonce")}, "id_token_nonce": {"other-nonce"}})

		assert.Equal(t, "The supplied nonce does not match the nonce from the id_token", gjson.GetBytes(body, "error.reason").String(), "%s", body)
		assert.Empty(t, linkedSubjects(t, i.ID))
	})

	t.Run("case=subject linked to another identity is rejected", func(t *testing.T) {
		subject := x.NewUUID().String()
		first := newPasswordIdentity(t)
		firstClient := testhelpers.NewHTTPClientWithIdentitySessionToken(t, ctx, reg, first)
		nonce := x.NewUUID().String()
		res, body := submitLink(t, firstClient, url.Values{"id_token": {idToken(subject, nonce)}, "id_token_nonce": {nonce}})
		require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)

		second := newPasswordIdentity(t)
		secondClient := testhelpers.NewHTTPClientWithIdentitySessionToken(t, ctx, reg, second)
		nonce = x.NewUUID().String()
		res, body = submitLink(t, secondClient, url.Values{"id_token": {idToken(subject, nonce)}, "id_token_nonce": {nonce}})

		assert.NotEqual(t, http.StatusOK, res.StatusCode, "%s", body)
		assert.Empty(t, linkedSubjects(t, second.ID))
		assert.Equal(t, []string{subject}, linkedSubjects(t, first.ID))
	})

	t.Run("case=already linked provider is rejected", func(t *testing.T) {
		i := newPasswordIdentity(t)
		client := testhelpers.NewHTTPClientWithIdentitySessionToken(t, ctx, reg, i)
		subject, nonce := x.NewUUID().String(), x.NewUUID().String()
		res, body := submitLink(t, client, url.Values{"id_token": {idToken(subject, nonce)}, "id_token_nonce": {nonce}})
		require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)

		otherSubject := x.NewUUID().String()
		nonce = x.NewUUID().String()
		res, body = submitLink(t, client, url.Values{"id_token": {idToken(otherSubject, nonce)}, "id_token_nonce": {nonce}})

		assert.Equal(t, http.StatusBadRequest, res.StatusCode, "%s", body)
		assert.Contains(t, gjson.GetBytes(body, "ui.messages.0.text").String(), "can not link unknown or already existing OpenID Connect connection", "%s", body)
		assert.Equal(t, []string{subject}, linkedSubjects(t, i.ID))
	})
}

// Fandom-end [SPLAT-1086]
