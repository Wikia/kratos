// Copyright © 2026 Fandom
// SPDX-License-Identifier: Apache-2.0

package hook

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fandom [SPLAT-1086]: the webhooks forward req.Form as ctx.fields for both browser (form-encoded)
// and API/native (JSON) flows. The hooks call req.ParseForm() first, then mergeJSONBodyIntoForm.
func TestMergeJSONBodyIntoForm(t *testing.T) {
	parseAndMerge := func(t *testing.T, req *http.Request) url.Values {
		if req.Body != nil {
			require.NoError(t, req.ParseForm())
		}
		require.NoError(t, mergeJSONBodyIntoForm(req))
		return req.Form
	}

	t.Run("case=form body keeps the existing behaviour", func(t *testing.T) {
		form := url.Values{"method": {"password"}, "identifier": {"alice"}, "age": {"30"}}
		req := httptest.NewRequest(http.MethodPost, "/self-service/login?flow=1", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		fields := parseAndMerge(t, req)
		assert.Equal(t, "password", fields.Get("method"))
		assert.Equal(t, "alice", fields.Get("identifier"))
		assert.Equal(t, "30", fields.Get("age"))
		assert.Equal(t, "1", fields.Get("flow"), "query parameters stay part of the fields, as before")
	})

	t.Run("case=json body is merged in the same shape", func(t *testing.T) {
		body := `{"method":"password","identifier":"alice","password":"secret","age":30,"tos-consent":true,` +
			`"traits":{"username":"alice","email":"a@example.org"},"transient_payload":{"language":"en"},` +
			`"tags":["a","b"],"nothing":null}`
		req := httptest.NewRequest(http.MethodPost, "/self-service/registration?flow=2", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json; charset=utf-8")

		fields := parseAndMerge(t, req)
		assert.Equal(t, "password", fields.Get("method"))
		assert.Equal(t, "alice", fields.Get("identifier"))
		assert.Equal(t, "30", fields.Get("age"), "numbers keep their literal form")
		assert.Equal(t, "true", fields.Get("tos-consent"))
		assert.Equal(t, "alice", fields.Get("traits.username"), "nested objects become dotted keys like form fields")
		assert.Equal(t, "a@example.org", fields.Get("traits.email"))
		assert.Equal(t, "en", fields.Get("transient_payload.language"))
		assert.Equal(t, []string{"a", "b"}, fields["tags"], "arrays become repeated values")
		assert.Empty(t, fields["nothing"], "null values are omitted")
		assert.Equal(t, "2", fields.Get("flow"), "query parameters from ParseForm are kept")

		// The body must still be readable by whoever runs after the hook.
		replayed, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.Equal(t, body, string(replayed))
	})

	t.Run("case=json body that is not an object is ignored", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/self-service/login?flow=3", strings.NewReader(`["not","an","object"]`))
		req.Header.Set("Content-Type", "application/json")

		assert.Equal(t, url.Values{"flow": {"3"}}, parseAndMerge(t, req))
	})

	t.Run("case=empty json body yields query parameters only", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/self-service/login?flow=4", bytes.NewReader(nil))
		req.Header.Set("Content-Type", "application/json")

		assert.Equal(t, url.Values{"flow": {"4"}}, parseAndMerge(t, req))
	})

	t.Run("case=request without body is untouched", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/self-service/login/api", nil)
		req.Body = nil

		require.NoError(t, mergeJSONBodyIntoForm(req))
		assert.Nil(t, req.Form, "unchanged: hooks without a body never parsed anything")
	})
}
