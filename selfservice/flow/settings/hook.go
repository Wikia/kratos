package settings

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gofrs/uuid"

	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/node"

	"github.com/ory/kratos/schema"
	"github.com/ory/x/sqlcon"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/x"
)

type (
	PostHookPrePersistExecutor interface {
		ExecuteSettingsPrePersistHook(w http.ResponseWriter, r *http.Request, a *Flow, s *identity.Identity) error
	}
	PostHookPrePersistExecutorFunc func(w http.ResponseWriter, r *http.Request, a *Flow, s *identity.Identity) error
	PostHookPostPersistExecutor    interface {
		ExecuteSettingsPostPersistHook(w http.ResponseWriter, r *http.Request, a *Flow, s *identity.Identity) error
	}
	PostHookPostPersistExecutorFunc func(w http.ResponseWriter, r *http.Request, a *Flow, s *identity.Identity) error
	HooksProvider                   interface {
		PostSettingsPrePersistHooks(ctx context.Context, settingsType string) []PostHookPrePersistExecutor
		PostSettingsPostPersistHooks(ctx context.Context, settingsType string) []PostHookPostPersistExecutor
	}
	executorDependencies interface {
		identity.ManagementProvider
		identity.ValidationProvider
		config.Provider

		HandlerProvider
		HooksProvider
		FlowPersistenceProvider

		x.LoggingProvider
		x.WriterProvider
	}
	HookExecutor struct {
		d executorDependencies
	}
	HookExecutorProvider interface {
		SettingsHookExecutor() *HookExecutor
	}
)

func (f PostHookPrePersistExecutorFunc) ExecuteSettingsPrePersistHook(w http.ResponseWriter, r *http.Request, a *Flow, s *identity.Identity) error {
	return f(w, r, a, s)
}

func (f PostHookPostPersistExecutorFunc) ExecuteSettingsPostPersistHook(w http.ResponseWriter, r *http.Request, a *Flow, s *identity.Identity) error {
	return f(w, r, a, s)
}

func PostHookPostPersistExecutorNames(e []PostHookPostPersistExecutor) []string {
	names := make([]string, len(e))
	for k, ee := range e {
		names[k] = fmt.Sprintf("%T", ee)
	}
	return names
}

func PostHookPrePersistExecutorNames(e []PostHookPrePersistExecutor) []string {
	names := make([]string, len(e))
	for k, ee := range e {
		names[k] = fmt.Sprintf("%T", ee)
	}
	return names
}

func NewHookExecutor(d executorDependencies) *HookExecutor {
	return &HookExecutor{d: d}
}

type PostSettingsHookOption func(o *postSettingsHookOptions)

type postSettingsHookOptions struct {
	cb func(ctxUpdate *UpdateContext) error
}

func WithCallback(cb func(ctxUpdate *UpdateContext) error) func(o *postSettingsHookOptions) {
	return func(o *postSettingsHookOptions) {
		o.cb = cb
	}
}

func (e *HookExecutor) PostSettingsHook(w http.ResponseWriter, r *http.Request, settingsType string, ctxUpdate *UpdateContext, i *identity.Identity, opts ...PostSettingsHookOption) error {
	var rand, _ = uuid.DefaultGenerator.NewV1()
	e.d.Logger().
		WithRequest(r).
		WithField("identity_id", i.ID).
		WithField("flow_method", settingsType).
		Debug("Running PostSettingsPrePersistHooks. ", rand)

	config := new(postSettingsHookOptions)
	for _, f := range opts {
		f(config)
	}

	for k, executor := range e.d.PostSettingsPrePersistHooks(r.Context(), settingsType) {
		logFields := logrus.Fields{
			"executor":          fmt.Sprintf("%T", executor),
			"executor_position": k,
			"executors":         PostHookPrePersistExecutorNames(e.d.PostSettingsPrePersistHooks(r.Context(), settingsType)),
			"identity_id":       i.ID,
			"flow_method":       settingsType,
		}
		e.d.Logger().WithRequest(r).WithFields(logFields).Debug("ExecuteSettingsPrePersistHook started. ", rand)

		if err := executor.ExecuteSettingsPrePersistHook(w, r, ctxUpdate.Flow, i); err != nil {
			if errors.Is(err, ErrHookAbortRequest) {
				e.d.Logger().WithRequest(r).WithFields(logFields).
					Debug("A ExecuteSettingsPrePersistHook hook aborted early.")
				return nil
			}
			e.d.Logger().WithRequest(r).WithFields(logFields).
				Error("Hook error: ", err)
			return err
		}

		e.d.Logger().WithRequest(r).WithFields(logFields).Debug("ExecuteSettingsPrePersistHook completed successfully. ", rand)
	}

	options := []identity.ManagerOption{identity.ManagerExposeValidationErrorsForInternalTypeAssertion}
	ttl := e.d.Config(r.Context()).SelfServiceFlowSettingsPrivilegedSessionMaxAge()
	if ctxUpdate.Session.AuthenticatedAt.Add(ttl).After(time.Now()) {
		options = append(options, identity.ManagerAllowWriteProtectedTraits)
	}
	e.d.Audit().
		WithRequest(r).
		WithField("identity_id", i.ID).
		Debug("Starting update. ", rand)

	if err := e.d.IdentityManager().Update(r.Context(), i, options...); err != nil {
		if errors.Is(err, identity.ErrProtectedFieldModified) {
			e.d.Logger().WithError(err).Debug("Modifying protected field requires re-authentication.")
			return errors.WithStack(NewFlowNeedsReAuth())
		}
		if errors.Is(err, sqlcon.ErrUniqueViolation) {
			return schema.NewDuplicateCredentialsError()
		}
		return err
	}
	e.d.Audit().
		WithRequest(r).
		WithField("identity_id", i.ID).
		Debug("An identity's settings have been updated. ", rand)

	ctxUpdate.UpdateIdentity(i)
	ctxUpdate.Flow.State = StateSuccess
	if config.cb != nil {
		if err := config.cb(ctxUpdate); err != nil {
			return err
		}
	}

	e.d.Audit().
		WithRequest(r).
		WithField("identity_id", i.ID).
		Debug("New settings flow ", rand)
	newFlow, err := e.d.SettingsHandler().NewFlow(w, r, i, ctxUpdate.Flow.Type)
	if err != nil {
		return err
	}

	e.d.Audit().
		WithRequest(r).
		WithField("identity_id", i.ID).
		Debug("New settings flow fin", rand)
	ctxUpdate.Flow.UI = newFlow.UI
	ctxUpdate.Flow.UI.ResetMessages()
	ctxUpdate.Flow.UI.AddMessage(node.DefaultGroup, text.NewInfoSelfServiceSettingsUpdateSuccess())

	e.d.Audit().
		WithRequest(r).
		WithField("identity_id", i.ID).
		Debug("Update settings flow ", rand)
	if err := e.d.SettingsFlowPersister().UpdateSettingsFlow(r.Context(), ctxUpdate.Flow); err != nil {
		return err
	}

	e.d.Audit().
		WithRequest(r).
		WithField("identity_id", i.ID).
		Debug("Update settings flow fin, start hooks ", rand)
	for k, executor := range e.d.PostSettingsPostPersistHooks(r.Context(), settingsType) {
		e.d.Logger().WithRequest(r).
			WithField("executor", fmt.Sprintf("%T", executor)).
			WithField("executor_position", k).
			WithField("executors", PostHookPostPersistExecutorNames(e.d.PostSettingsPostPersistHooks(r.Context(), settingsType))).
			WithField("identity_id", i.ID).
			WithField("flow_method", settingsType).
			Debug("Eggzecutor run ", rand)
		if err := executor.ExecuteSettingsPostPersistHook(w, r, ctxUpdate.Flow, i); err != nil {
			if errors.Is(err, ErrHookAbortRequest) {
				e.d.Logger().
					WithRequest(r).
					WithField("executor", fmt.Sprintf("%T", executor)).
					WithField("executor_position", k).
					WithField("executors", PostHookPostPersistExecutorNames(e.d.PostSettingsPostPersistHooks(r.Context(), settingsType))).
					WithField("identity_id", i.ID).
					WithField("flow_method", settingsType).
					Debug("A ExecuteSettingsPostPersistHook hook aborted early.")
				return nil
			}
			return err
		}

		e.d.Logger().WithRequest(r).
			WithField("executor", fmt.Sprintf("%T", executor)).
			WithField("executor_position", k).
			WithField("executors", PostHookPostPersistExecutorNames(e.d.PostSettingsPostPersistHooks(r.Context(), settingsType))).
			WithField("identity_id", i.ID).
			WithField("flow_method", settingsType).
			Debug("ExecuteSettingsPostPersistHook completed successfully. ", rand)
	}

	e.d.Logger().
		WithRequest(r).
		WithField("identity_id", i.ID).
		WithField("flow_method", settingsType).
		Debug("Completed all PostSettingsPrePersistHooks and PostSettingsPostPersistHooks. ", rand)
	e.d.Logger().Debug("Let's check the flow type ", rand)
	if ctxUpdate.Flow.Type == flow.TypeAPI || x.IsJSONRequest(r) {
		updatedFlow, err := e.d.SettingsFlowPersister().GetSettingsFlow(r.Context(), ctxUpdate.Flow.ID)
		if err != nil {
			return err
		}

		e.d.Writer().Write(w, r, &APIFlowResponse{Flow: updatedFlow, Identity: i})
		return nil
	}
	e.d.Logger().Debug("This is not an api flow", rand)
	time.Sleep(time.Second)
	defer func() {
		e.d.Logger().Debug("finished returning", rand)
		time.Sleep(time.Second)
		e.d.Logger().Debug("finished returning2", rand)
	}()
	return nil
	//return x.SecureContentNegotiationRedirection(w, r, ctxUpdate.GetIdentityToUpdate().CopyWithoutCredentials(), ctxUpdate.Flow.RequestURL, e.d.Writer(), e.d.Config(r.Context()),
	//	x.SecureRedirectOverrideDefaultReturnTo(
	//		e.d.Config(r.Context()).SelfServiceFlowSettingsReturnTo(settingsType,
	//			ctxUpdate.Flow.AppendTo(e.d.Config(r.Context()).SelfServiceFlowSettingsUI()))))
}
