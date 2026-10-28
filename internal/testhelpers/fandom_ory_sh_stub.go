// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package testhelpers

import (
	"io"
	"net/http"
	"strings"

	"github.com/jarcoal/httpmock"
)

// fandom change [SPLAT-1118]: many upstream tests use https://www.ory.sh/... as the return_to target and follow the
// redirect over the internet. www.ory.sh now redirects to www.ory.com, so every assertion on the final URL failed.
// Answer requests to www.ory.sh locally with an empty 200, so the final URL is the one Kratos redirected to.
// This package is only linked into tests.
const stubbedRedirectHost = "www.ory.sh"

type stubbedRedirectTransport struct {
	next http.RoundTripper
}

func (t *stubbedRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != stubbedRedirectHost {
		return t.next.RoundTrip(req)
	}
	if req.Body != nil {
		_ = req.Body.Close()
	}
	return &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/html"}},
		Body:          io.NopCloser(strings.NewReader("")),
		ContentLength: 0,
		Request:       req,
	}, nil
}

func init() {
	http.DefaultTransport = &stubbedRedirectTransport{next: http.DefaultTransport}
	// httpmock.Deactivate restores the transport it saved when it was loaded, which would drop the stub
	httpmock.InitialTransport = http.DefaultTransport
}

// fandom change - end
