// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package sql

import (
	"context"
	"embed"
	stderrors "errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/laher/mergefs"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/persistence"
	"github.com/ory/kratos/persistence/sql/devices"
	idpersistence "github.com/ory/kratos/persistence/sql/identity"
	"github.com/ory/kratos/schema"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
	"github.com/ory/x/contextx"
	"github.com/ory/x/networkx"
	"github.com/ory/x/otelx"
	"github.com/ory/x/popx"
	"github.com/ory/x/sqlcon"
)

var _ persistence.Persister = new(Persister)

//go:embed migrations/sql/*.sql
var migrations embed.FS

type (
	persisterDependencies interface {
		x.LoggingProvider
		config.Provider
		contextx.Provider
		x.TracingProvider
		schema.IdentitySchemaProvider
		identity.ValidationProvider
	}
	Persister struct {
		nid uuid.UUID
		c   *pop.Connection
		mb  *popx.MigrationBox
		mbs popx.MigrationStatuses
		r   persisterDependencies
		p   *networkx.Manager

		identity.PrivilegedPool
		session.DevicePersister
	}
)

type persisterOptions struct {
	extraMigrations []fs.FS
	disableLogging  bool
}

type persisterOption func(o *persisterOptions)

func WithExtraMigrations(fss ...fs.FS) persisterOption {
	return func(o *persisterOptions) {
		o.extraMigrations = fss
	}
}

func WithDisabledLogging(v bool) persisterOption {
	return func(o *persisterOptions) {
		o.disableLogging = v
	}
}

func NewPersister(ctx context.Context, r persisterDependencies, c *pop.Connection, opts ...persisterOption) (*Persister, error) {
	o := &persisterOptions{}
	for _, f := range opts {
		f(o)
	}
	logger := r.Logger()
	if o.disableLogging {
		logger.Logrus().SetLevel(logrus.WarnLevel)
	}
	m, err := popx.NewMigrationBox(
		mergefs.Merge(
			append(
				[]fs.FS{
					migrations, networkx.Migrations,
				},
				o.extraMigrations...,
			)...,
		),
		popx.NewMigrator(c, logger, r.Tracer(ctx), 0),
	)
	if err != nil {
		return nil, err
	}

	m.DumpMigrations = false
	return &Persister{
		c:               c,
		mb:              m,
		r:               r,
		PrivilegedPool:  idpersistence.NewPersister(r, c),
		DevicePersister: devices.NewPersister(r, c),
		p:               networkx.NewManager(c, r.Logger(), r.Tracer(ctx)),
	}, nil
}

func (p *Persister) NetworkID(ctx context.Context) uuid.UUID {
	return p.r.Contextualizer().Network(ctx, p.nid)
}

func (p Persister) WithNetworkID(nid uuid.UUID) persistence.Persister {
	p.nid = nid
	if pp, ok := p.PrivilegedPool.(interface {
		WithNetworkID(uuid.UUID) identity.PrivilegedPool
	}); ok {
		p.PrivilegedPool = pp.WithNetworkID(nid)
	}
	if dp, ok := p.DevicePersister.(interface {
		WithNetworkID(uuid.UUID) session.DevicePersister
	}); ok {
		p.DevicePersister = dp.WithNetworkID(nid)
	}
	return &p
}

func (p *Persister) DetermineNetwork(ctx context.Context) (*networkx.Network, error) {
	return p.p.Determine(ctx)
}

func (p *Persister) Connection(ctx context.Context) *pop.Connection {
	return p.c.WithContext(ctx)
}

func (p *Persister) MigrationStatus(ctx context.Context) (_ popx.MigrationStatuses, err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.MigrationStatus")
	defer otelx.End(span, &err)

	if p.mbs != nil {
		return p.mbs, nil
	}

	status, err := p.mb.Status(ctx)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !status.HasPending() {
		p.mbs = status
	}

	return status, nil
}

func (p *Persister) MigrateDown(ctx context.Context, steps int) error {
	return p.mb.Down(ctx, steps)
}

func (p *Persister) MigrateUp(ctx context.Context) error {
	return p.mb.Up(ctx)
}

func (p *Persister) MigrationBox() *popx.MigrationBox {
	return p.mb
}

func (p *Persister) Migrator() *popx.Migrator {
	return p.mb.Migrator
}

func (p *Persister) Close(ctx context.Context) error {
	return errors.WithStack(p.GetConnection(ctx).Close())
}

func (p *Persister) Ping() error {
	type pinger interface {
		Ping() error
	}

	// This can not be contextualized because of some gobuffalo/pop limitations.
	return errors.WithStack(p.c.Store.(pinger).Ping())
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}

	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (p *Persister) deleteExpired(ctx context.Context, table string, column string, cutoff time.Time, batchSize int) (err error) {
	pause := p.r.Config().DatabaseCleanupSleepTables(ctx)
	deleted := 0

	defer func() {
		l := p.r.Logger().WithField("table", table).WithField("deleted", deleted)
		if err != nil {
			l.Warn("Cleanup stopped before the table was drained")
			return
		}
		l.Info("Cleaned up expired records")
	}()

	for {
		var n int
		n, err = p.deleteExpiredBatch(ctx, table, column, cutoff, batchSize)
		deleted += n
		if err != nil {
			return err
		}

		if n < batchSize || n == 0 {
			return nil
		}

		if err = sleep(ctx, pause); err != nil {
			return err
		}
	}
}

func (p *Persister) deleteExpiredBatch(ctx context.Context, table string, column string, cutoff time.Time, limit int) (int, error) {
	conn := p.GetConnection(ctx)

	type idRow struct {
		ID uuid.UUID `db:"id"`
	}
	var rows []idRow

	//#nosec G201 -- table and column are static
	if err := conn.RawQuery(fmt.Sprintf(
		"SELECT id FROM %s WHERE %s <= ? ORDER BY %s ASC LIMIT %d",
		table, column, column, limit,
	), cutoff).All(&rows); err != nil {
		return 0, sqlcon.HandleError(err)
	}

	if len(rows) == 0 {
		return 0, nil
	}

	ids := make([]interface{}, len(rows))
	placeholders := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
		placeholders[i] = "?"
	}

	//#nosec G201 -- table is static
	if err := conn.RawQuery(
		fmt.Sprintf("DELETE FROM %s WHERE id IN (%s)", table, strings.Join(placeholders, ",")),
		ids...,
	).Exec(); err != nil {
		return 0, sqlcon.HandleError(err)
	}

	return len(rows), nil
}

func (p *Persister) CleanupDatabase(ctx context.Context, wait time.Duration, older time.Duration, batchSize int) error {
	currentTime := time.Now().Add(-older)
	p.r.Logger().Printf("Cleaning up records older than %s\n", currentTime)

	steps := []struct {
		what string
		run  func() error
	}{
		{"expired sessions", func() error { return p.DeleteExpiredSessions(ctx, currentTime, batchSize) }},
		{"expired continuity containers", func() error { return p.DeleteExpiredContinuitySessions(ctx, currentTime, batchSize) }},
		{"expired login flows", func() error { return p.DeleteExpiredLoginFlows(ctx, currentTime, batchSize) }},
		{"expired recovery flows", func() error { return p.DeleteExpiredRecoveryFlows(ctx, currentTime, batchSize) }},
		{"expired registration flows", func() error { return p.DeleteExpiredRegistrationFlows(ctx, currentTime, batchSize) }},
		{"expired settings flows", func() error { return p.DeleteExpiredSettingsFlows(ctx, currentTime, batchSize) }},
		{"expired verification flows", func() error { return p.DeleteExpiredVerificationFlows(ctx, currentTime, batchSize) }},
		{"expired session token exchangers", func() error { return p.DeleteExpiredExchangers(ctx, currentTime, batchSize) }},
		{"seen selfservice errors", func() error { return p.ClearErrorContainers(ctx, older, false) }},
	}

	var failures []error
	for i, step := range steps {
		p.r.Logger().Println("Cleaning up " + step.what)

		if err := step.run(); err != nil {
			// A cancelled context means we ran out of time, so there is no point
			// in trying the remaining steps.
			if ctx.Err() != nil {
				break
			}

			p.r.Logger().WithError(err).Error("Unable to clean up " + step.what + ", continuing with the remaining tables")
			failures = append(failures, errors.Wrap(err, step.what))
			continue
		}

		if i < len(steps)-1 {
			if err := sleep(ctx, wait); err != nil {
				break
			}
		}
	}

	if err := ctx.Err(); err != nil {
		failures = append(failures, errors.Wrap(err, "cleanup ran out of time"))
	}

	if len(failures) > 0 {
		return errors.WithStack(stderrors.Join(failures...))
	}

	p.r.Logger().Println("Successfully cleaned up the SQL database! " +
		"This should be re-run periodically, to be sure that all expired data is purged.")
	return nil
}
