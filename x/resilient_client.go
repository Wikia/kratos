package x

import (
	"github.com/ory/x/httpx"

	"github.com/hashicorp/go-retryablehttp"
)

type ResilientClientProvider interface {
	GetSpecializedResilientClient(name string, opts ...httpx.ResilientOptions) *retryablehttp.Client
}
