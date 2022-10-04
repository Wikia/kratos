package x

import (
	"context"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/ory/x/httpx"
)

type ResilientClientProvider interface {
	NamedHTTPClient(ctx context.Context, name string, opts ...httpx.ResilientOptions) *retryablehttp.Client
}
