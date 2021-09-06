package x

import (
	"github.com/hashicorp/go-retryablehttp"
)

type ResilientClientProvider interface {
	GetResilientClient() *retryablehttp.Client
}
