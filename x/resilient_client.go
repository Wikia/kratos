package x

import (
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

type ResilientClientProvider interface {
	GetSpecializedResilientClient(name string, retries int, timeout time.Duration, minWait time.Duration, maxWait time.Duration) *retryablehttp.Client
}
