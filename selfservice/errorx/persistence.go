// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package errorx

import (
	"context"
	"time"

	"github.com/gofrs/uuid"
)

type (
	Persister interface {
		// CreateErrorContainer adds an error to the manager and returns a
		// unique identifier or an error if insertion fails.
		CreateErrorContainer(ctx context.Context, csrfToken string, err error) (uuid.UUID, error)

		// ReadErrorContainer returns an error by its unique identifier and
		// marks the error as read. If an error occurs during retrieval the
		// second return parameter is an error.
		ReadErrorContainer(ctx context.Context, id uuid.UUID) (*ErrorContainer, error)

		// fandom-start
		ClearErrorContainers(ctx context.Context, expiresAt time.Time, limit int) error
		// fandom-end
	}

	PersistenceProvider interface {
		SelfServiceErrorPersister() Persister
	}
)
