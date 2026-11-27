// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package hook

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// fandom change: Cloudflare bot signals reach the web hook body, SPLAT-1124
func TestRemoveDisallowedHeadersKeepsBotSignals(t *testing.T) {
	botHeaders := []string{
		"X-Fandom-Bot",
		"X-Fandom-Bot-Name",
		"X-Fandom-Bot-Score",
		"X-Fandom-Bot-Tags",
		"X-Fandom-Bot-Category",
		"X-Fandom-Bot-Corporate-Proxy",
		"X-Fandom-Bot-JS-Passed", // as Cloudflare names it; canonicalised to X-Fandom-Bot-Js-Passed
		"X-Fandom-JA3",
		"X-Fandom-Ja4",
		"X-Fandom-Name",
		"X-Fandom-Browser",
	}

	in := http.Header{}
	for _, h := range botHeaders {
		in.Set(h, "value")
	}
	in.Set("Some-Header", "dropped")

	data := &templateContext{RequestHeaders: in}
	removeDisallowedHeaders(data)

	for _, h := range botHeaders {
		assert.Equal(t, "value", data.RequestHeaders.Get(h), h)
	}
	assert.Empty(t, data.RequestHeaders.Get("Some-Header"))
	assert.Len(t, data.RequestHeaders, len(botHeaders))
}
