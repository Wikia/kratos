// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package password_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/x"
)

// fandom change [SPLAT-1118]: user-registration answers the pre-persist registration webhook with
// {"identity":{"metadata_public":{"user_id":...}}}. Pin that Kratos persists it and returns it in the API registration
// response, so the mobile app can read the user id without a whoami call.
func TestRegistrationWebhookSetsMetadataPublic(t *testing.T) {
	ctx := context.Background()
	reg := newRegistrationRegistry(t)
	conf := reg.Config()

	publicTS, _ := testhelpers.NewKratosServerWithRouters(t, reg, x.NewRouterPublic(), x.NewRouterAdmin())
	_ = testhelpers.NewErrorTestServer(t, reg)
	_ = testhelpers.NewRegistrationUIFlowEchoServer(t, reg)
	testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/registration.schema.json")

	var hookIdentityID string
	webhookTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		hookIdentityID = gjson.GetBytes(body, "identityId").String()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"identity":{"metadata_public":{"email_verified":false,"user_id":"12345"}}}`))
	}))
	t.Cleanup(webhookTS.Close)

	template := base64.StdEncoding.EncodeToString([]byte(`function(ctx) { identityId: ctx.identity.id }`))
	webhookConfig := json.RawMessage(fmt.Sprintf(`{"url": %q, "method": "POST", "body": "base64://%s", "can_interrupt": true, "response": {"parse": true}}`, webhookTS.URL, template))
	conf.MustSet(ctx, config.HookStrategyKey(config.ViperKeySelfServiceRegistrationAfter, identity.CredentialsTypePassword.String()), []config.SelfServiceHook{
		{Name: "session"},
		{Name: "web_hook", PersistencePhase: config.PrePersist, Config: webhookConfig},
	})

	body := testhelpers.SubmitRegistrationForm(t, true, nil, publicTS, func(v url.Values) {
		v.Set("traits.username", "registration-metadata-public-api")
		v.Set("password", x.NewUUID().String())
		v.Set("traits.foobar", "bar")
	}, false, http.StatusOK, publicTS.URL+registration.RouteSubmitFlow)

	identityID := gjson.Get(body, "identity.id").String()
	require.NotEmpty(t, identityID, "%s", body)
	assert.Equal(t, identityID, hookIdentityID, "the webhook sees the id the identity is persisted with")
	assert.JSONEq(t, `{"email_verified":false,"user_id":"12345"}`, gjson.Get(body, "identity.metadata_public").Raw, "%s", body)
	assert.JSONEq(t, `{"email_verified":false,"user_id":"12345"}`, gjson.Get(body, "session.identity.metadata_public").Raw, "%s", body)

	persisted, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, uuid.FromStringOrNil(identityID))
	require.NoError(t, err)
	assert.JSONEq(t, `{"email_verified":false,"user_id":"12345"}`, string(persisted.MetadataPublic))
}

// fandom change - end
