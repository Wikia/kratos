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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/x"
)

// fandom change [SPLAT-1118]: the after-submit hook (rate limit and captcha) runs before the strategy copies the
// submitted transient_payload onto the flow. Clients that only send stock Kratos fields put the captcha token into
// transient_payload, so the hook must see ctx.flow.transient_payload for form and JSON submits, also when the
// password is wrong. The top-level captcha_token field the web sends keeps working through ctx.fields.
func TestLoginAfterSubmitHookSeesTransientPayload(t *testing.T) {
	ctx := context.Background()
	reg := newRegistrationRegistry(t)
	conf := reg.Config()
	publicTS, _ := testhelpers.NewKratosServerWithRouters(t, reg, x.NewRouterPublic(), x.NewRouterAdmin())
	_ = testhelpers.NewErrorTestServer(t, reg)
	_ = testhelpers.NewRegistrationUIFlowEchoServer(t, reg)
	_ = testhelpers.NewLoginUIFlowEchoServer(t, reg)
	testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/registration.schema.json")
	conf.MustSet(ctx, config.HookStrategyKey(config.ViperKeySelfServiceRegistrationAfter, identity.CredentialsTypePassword.String()), []config.SelfServiceHook{{Name: "session"}})

	var hookBody string
	hookTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		hookBody = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(hookTS.Close)
	template := base64.StdEncoding.EncodeToString([]byte(`function(ctx) {
  transient_payload: if std.objectHas(ctx.flow, "transient_payload") then ctx.flow.transient_payload else null,
  captcha_field: if std.objectHas(ctx.fields, "captcha_token") then ctx.fields.captcha_token[0] else null,
}`))
	conf.MustSet(ctx, config.ViperKeySelfServiceLoginAfterSubmitHooks, []config.SelfServiceHook{{
		Name:   "web_hook",
		Config: json.RawMessage(fmt.Sprintf(`{"url": %q, "method": "POST", "body": "base64://%s", "can_interrupt": true}`, hookTS.URL, template)),
	}})

	newFlow := func(t *testing.T, kind string) string {
		res, err := http.Get(publicTS.URL + "/self-service/" + kind + "/api")
		require.NoError(t, err)
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)
		return gjson.GetBytes(body, "id").String()
	}
	submit := func(t *testing.T, kind, flowID, contentType, body string) (int, string) {
		req, err := http.NewRequest(http.MethodPost, publicTS.URL+"/self-service/"+kind+"?flow="+flowID, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", contentType)
		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}

	username, password := "after-submit-"+strings.ReplaceAll(x.NewUUID().String(), "-", "")[:12], x.NewUUID().String()
	status, body := submit(t, "registration", newFlow(t, "registration"), "application/x-www-form-urlencoded", url.Values{
		"method": {"password"}, "password": {password}, "traits.username": {username}, "traits.foobar": {"bar"},
	}.Encode())
	require.Equal(t, http.StatusOK, status, "%s", body)

	formLogin := func(password string, extra url.Values) string {
		v := url.Values{"method": {"password"}, "identifier": {username}, "password": {password}}
		for k, vv := range extra {
			v[k] = vv
		}
		return v.Encode()
	}

	for _, tc := range []struct {
		name, contentType, body string
		expectedStatus          int
		expectedPayload         string
		expectedField           string
	}{
		{
			name:            "form with transient_payload",
			contentType:     "application/x-www-form-urlencoded; charset=UTF-8",
			body:            formLogin(password, url.Values{"transient_payload": {`{"captcha_token":"from-payload"}`}}),
			expectedStatus:  http.StatusOK,
			expectedPayload: `{"captcha_token":"from-payload"}`,
		},
		{
			name:            "form with transient_payload and a wrong password",
			contentType:     "application/x-www-form-urlencoded; charset=UTF-8",
			body:            formLogin("wrong-password", url.Values{"transient_payload": {`{"captcha_token":"from-payload"}`}}),
			expectedStatus:  http.StatusBadRequest,
			expectedPayload: `{"captcha_token":"from-payload"}`,
		},
		{
			name:            "json with transient_payload",
			contentType:     "application/json",
			body:            fmt.Sprintf(`{"method":"password","identifier":%q,"password":%q,"transient_payload":{"captcha_token":"from-json"}}`, username, password),
			expectedStatus:  http.StatusOK,
			expectedPayload: `{"captcha_token":"from-json"}`,
		},
		{
			name:           "form with the top-level captcha_token field",
			contentType:    "application/x-www-form-urlencoded",
			body:           formLogin(password, url.Values{"captcha_token": {"from-field"}}),
			expectedStatus: http.StatusOK,
			expectedField:  "from-field",
		},
	} {
		t.Run("case="+tc.name, func(t *testing.T) {
			hookBody = ""
			status, body := submit(t, "login", newFlow(t, "login"), tc.contentType, tc.body)
			require.Equal(t, tc.expectedStatus, status, "%s", body)
			if tc.expectedStatus == http.StatusOK {
				assert.NotEmpty(t, gjson.Get(body, "session_token").String(), "%s", body)
			}

			require.NotEmpty(t, hookBody, "the after-submit hook must have run")
			if tc.expectedPayload == "" {
				assert.Equal(t, "null", gjson.Get(hookBody, "transient_payload").Raw, "%s", hookBody)
			} else {
				assert.JSONEq(t, tc.expectedPayload, gjson.Get(hookBody, "transient_payload").Raw, "%s", hookBody)
			}
			if tc.expectedField == "" {
				assert.Equal(t, "null", gjson.Get(hookBody, "captcha_field").Raw, "%s", hookBody)
			} else {
				assert.Equal(t, tc.expectedField, gjson.Get(hookBody, "captcha_field").String(), "%s", hookBody)
			}
		})
	}
}

// fandom change - end
