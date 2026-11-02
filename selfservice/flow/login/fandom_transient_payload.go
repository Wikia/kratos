// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"

	"github.com/tidwall/gjson"
)

// fandom change [SPLAT-1118]: the login strategies copy the submitted transient_payload onto the flow only after the
// after-submit hooks ran, so those hooks (rate limit and captcha) could not read ctx.flow.transient_payload. Clients
// that only send stock Kratos fields (e.g. the mobile app sending its captcha token in transient_payload) need it
// there. Reads it from a form-encoded or JSON body; the body stays readable for the strategy decoders.
func transientPayloadFromRequest(r *http.Request) json.RawMessage {
	if r.Body == nil {
		return nil
	}

	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType != "application/json" && mediaType != "application/x-www-form-urlencoded" {
		return nil
	}

	// Work on a copy of the body: parsing the request itself (r.ParseForm) would hide a malformed body from the
	// strategy decoders, which must still reject it.
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return nil
	}

	var raw string
	if mediaType == "application/json" {
		raw = gjson.GetBytes(body, "transient_payload").Raw
	} else {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return nil
		}
		raw = values.Get("transient_payload")
	}

	if !gjson.Valid(raw) || !gjson.Parse(raw).IsObject() {
		return nil
	}
	return json.RawMessage(raw)
}

// fandom change - end
