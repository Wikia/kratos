package cleanup

import (
	cx "context"
	"time"

	"github.com/ory/graceful"
	"github.com/ory/kratos/driver"
)

func BackgroundCleanup(ctx cx.Context, r driver.Registry) {
	ctx, cancel := cx.WithCancel(ctx)

	r.Logger().Println("Cleanup worker started.")
	if err := graceful.Graceful(func() error {
		for {
			select {
			case <-time.After(r.Config(ctx).DatabaseCleanupSleep()):
				err := r.Persister().CleanupDatabase(ctx, 30*time.Second)
				r.Logger().Error(err)
			case <-ctx.Done():
				return nil
			}
		}
	}, func(_ cx.Context) error {
		cancel()
		return nil
	}); err != nil {
		r.Logger().WithError(err).Fatalf("Failed to run cleanup worker.")
	}

	r.Logger().Println("Background cleanup worker was shutdown gracefully.")
}
