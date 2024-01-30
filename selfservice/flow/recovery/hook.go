// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package recovery

import (
	"context"
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel/trace"

	"github.com/ory/kratos/x/events"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/ui/container"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
)

type (
	PreHookExecutor interface {
		ExecuteRecoveryPreHook(w http.ResponseWriter, r *http.Request, a *Flow) error
	}
	PreHookExecutorFunc func(w http.ResponseWriter, r *http.Request, a *Flow) error

	PostHookExecutor interface {
		ExecutePostRecoveryHook(w http.ResponseWriter, r *http.Request, a *Flow, s *session.Session) error
	}
	PostHookExecutorFunc func(w http.ResponseWriter, r *http.Request, a *Flow, s *session.Session) error

	HooksProvider interface {
		PreRecoveryHooks(ctx context.Context) []PreHookExecutor
		PostRecoveryHooks(ctx context.Context) []PostHookExecutor
	}
)

func PostHookRecoveryExecutorNames(e []PostHookExecutor) []string {
	names := make([]string, len(e))
	for k, ee := range e {
		names[k] = fmt.Sprintf("%T", ee)
	}
	return names
}

func (f PreHookExecutorFunc) ExecuteRecoveryPreHook(w http.ResponseWriter, r *http.Request, a *Flow) error {
	return f(w, r, a)
}

func (f PostHookExecutorFunc) ExecutePostRecoveryHook(w http.ResponseWriter, r *http.Request, a *Flow, s *session.Session) error {
	return f(w, r, a, s)
}

type (
	executorDependencies interface {
		config.Provider
		identity.ManagementProvider
		identity.ValidationProvider
		session.PersistenceProvider
		HooksProvider
		x.CSRFTokenGeneratorProvider
		x.LoggingProvider
		x.WriterProvider
	}

	HookExecutor struct {
		d executorDependencies
	}

	HookExecutorProvider interface {
		RecoveryExecutor() *HookExecutor
	}
)

func NewHookExecutor(d executorDependencies) *HookExecutor {
	return &HookExecutor{
		d: d,
	}
}

func (e *HookExecutor) handleRecoveryError(_ http.ResponseWriter, r *http.Request, f *Flow, i *identity.Identity, flowError error) error {
	if f != nil {
		if i != nil {
			cont, err := container.NewFromStruct("", node.LinkGroup, i.Traits, "traits")
			if err != nil {
				e.d.Logger().WithField("error", err).Warn("could not update flow UI")
				return err
			}

			for _, n := range cont.Nodes {
				// we only set the value and not the whole field because we want to keep types from the initial form generation
				f.UI.Nodes.SetValueAttribute(n.ID(), n.Attributes.GetValue())
			}
		}

		if f.Type == flow.TypeBrowser {
			f.UI.SetCSRF(e.d.GenerateCSRFToken(r))
		}
	}

	return flowError
}

func (e *HookExecutor) PostRecoveryHook(w http.ResponseWriter, r *http.Request, a *Flow, s *session.Session) error {
	e.d.Logger().
		WithRequest(r).
		WithField("identity_id", s.Identity.ID).
		Debug("Running ExecutePostRecoveryHooks.")
	for k, executor := range e.d.PostRecoveryHooks(r.Context()) {
		if err := executor.ExecutePostRecoveryHook(w, r, a, s); err != nil {
			return e.handleRecoveryError(w, r, a, s.Identity, err)
		}

		e.d.Logger().WithRequest(r).
			WithField("executor", fmt.Sprintf("%T", executor)).
			WithField("executor_position", k).
			WithField("executors", PostHookRecoveryExecutorNames(e.d.PostRecoveryHooks(r.Context()))).
			WithField("identity_id", s.Identity.ID).
			Debug("ExecutePostRecoveryHook completed successfully.")
	}

	trace.SpanFromContext(r.Context()).AddEvent(events.NewRecoverySucceeded(r.Context(), s.Identity.ID, string(a.Type), a.Active.String()))

	e.d.Logger().
		WithRequest(r).
		WithField("identity_id", s.Identity.ID).
		Debug("Post recovery execution hooks completed successfully.")

	return nil
}

func (e *HookExecutor) PreRecoveryHook(w http.ResponseWriter, r *http.Request, a *Flow) error {
	for _, executor := range e.d.PreRecoveryHooks(r.Context()) {
		if err := executor.ExecuteRecoveryPreHook(w, r, a); err != nil {
			return err
		}
	}

	return nil
}
