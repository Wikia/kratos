// Copyright © 2026 Fandom
// SPDX-License-Identifier: Apache-2.0

package hook_test

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

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/selfservice/hook"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
	"github.com/ory/x/jsonnetsecure"
	"github.com/ory/x/logrusx"
	"github.com/ory/x/otelx"
)

// Fandom [SPLAT-1086]: the submitted fields reach the jsonnet template as ctx.fields for
// form-encoded (browser) and JSON (API / native) submits alike.
func TestWebHookForwardsSubmittedFields(t *testing.T) {
	_, reg := internal.NewFastRegistryWithMocks(t)
	logger := logrusx.New("kratos", "test")
	whDeps := struct {
		x.SimpleLoggerWithClient
		*jsonnetsecure.TestProvider
		x.ResilientClientProvider
	}{
		x.SimpleLoggerWithClient{L: logger, C: reg.HTTPClient(context.Background()), T: otelx.NewNoop(logger, &otelx.Config{ServiceName: "kratos"})},
		jsonnetsecure.NewTestProvider(t),
		reg,
	}

	var received string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		received = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)

	template := base64.StdEncoding.EncodeToString([]byte(`function(ctx) { fields: ctx.fields }`))
	conf := json.RawMessage(fmt.Sprintf(`{"url": %q, "method": "POST", "body": "base64://%s"}`, ts.URL, template))
	wh := hook.NewWebHook(&whDeps, conf)

	newRequest := func(contentType, body string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "https://www.ory.sh/self-service/login?flow=abc", strings.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		return req
	}
	formBody := url.Values{"method": {"password"}, "identifier": {"alice"}, "age": {"30"}}.Encode()
	jsonBody := `{"method":"password","identifier":"alice","age":30,"tos-consent":true,"traits":{"username":"alice"}}`

	assertCommonFields := func(t *testing.T) {
		assert.Equal(t, "password", gjson.Get(received, "fields.method.0").String(), received)
		assert.Equal(t, "alice", gjson.Get(received, "fields.identifier.0").String(), received)
		assert.Equal(t, "30", gjson.Get(received, "fields.age.0").String(), received)
		assert.Equal(t, "abc", gjson.Get(received, "fields.flow.0").String(), "query parameters are part of the fields")
	}

	for _, tc := range []struct {
		name        string
		contentType string
		body        string
		jsonOnly    bool
	}{
		{name: "form-encoded (browser flow)", contentType: "application/x-www-form-urlencoded", body: formBody},
		{name: "json (api flow)", contentType: "application/json", body: jsonBody, jsonOnly: true},
	} {
		t.Run("hook=login post/content="+tc.name, func(t *testing.T) {
			received = ""
			s := &session.Session{ID: x.NewUUID(), Identity: &identity.Identity{ID: x.NewUUID()}}
			f := &login.Flow{ID: x.NewUUID()}

			require.NoError(t, wh.ExecuteLoginPostHook(nil, newRequest(tc.contentType, tc.body), node.PasswordGroup, f, s))

			assertCommonFields(t)
			if tc.jsonOnly {
				assert.Equal(t, "true", gjson.Get(received, "fields.tos-consent.0").String())
				assert.Equal(t, "alice", gjson.Get(received, "fields.traits\\.username.0").String(), "nested JSON becomes dotted field names")
			}
		})

		t.Run("hook=after submit login/content="+tc.name, func(t *testing.T) {
			received = ""
			s := &session.Session{ID: x.NewUUID(), IdentityID: x.NewUUID()}
			f := &login.Flow{ID: x.NewUUID()}

			require.NoError(t, wh.ExecuteAfterSubmitLoginHook(nil, newRequest(tc.contentType, tc.body), f, s))

			assertCommonFields(t)
		})

		t.Run("hook=registration pre persist/content="+tc.name, func(t *testing.T) {
			received = ""
			i := &identity.Identity{ID: x.NewUUID(), Traits: identity.Traits(`{"username":"alice"}`)}
			f := &registration.Flow{ID: x.NewUUID()}

			require.NoError(t, wh.ExecutePostRegistrationPrePersistHook(nil, newRequest(tc.contentType, tc.body), f, i, identity.CredentialsTypePassword))

			assertCommonFields(t)
		})
	}

	t.Run("case=request body is still readable after the hooks ran", func(t *testing.T) {
		req := newRequest("application/json", jsonBody)
		s := &session.Session{ID: x.NewUUID(), Identity: &identity.Identity{ID: x.NewUUID()}}
		require.NoError(t, wh.ExecuteLoginPostHook(nil, req, node.PasswordGroup, &login.Flow{ID: x.NewUUID()}, s))

		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.JSONEq(t, jsonBody, string(body))
	})
}
