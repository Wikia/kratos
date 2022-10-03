package hook

import (
	"context"
	"crypto/md5" //nolint:gosec
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/request"
	"github.com/ory/kratos/schema"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/flow/recovery"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/kratos/selfservice/flow/verification"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/x"
	"github.com/ory/x/httpx"
	"github.com/ory/x/otelx"
)

var _ registration.PostHookPostPersistExecutor = new(WebHook)
var _ registration.PostHookPrePersistExecutor = new(WebHook)
var _ verification.PostHookExecutor = new(WebHook)
var _ recovery.PostHookExecutor = new(WebHook)
var _ settings.PostHookPostPersistExecutor = new(WebHook)

type (
	webHookDependencies interface {
		x.LoggingProvider
		x.HTTPClientProvider
		x.TracingProvider
		x.ResilientClientProvider
	}

	templateContext struct {
		Flow           flow.Flow          `json:"flow"`
		RequestHeaders http.Header        `json:"request_headers"`
		RequestMethod  string             `json:"request_method"`
		RequestUrl     string             `json:"request_url"`
		Identity       *identity.Identity `json:"identity,omitempty"`
		// fandom-start
		Credentials *identity.Credentials `json:"credentials,omitempty"`
		Fields      url.Values            `json:"fields,omitempty"`
		HookType    string                `json:"hook_type,omitempty"`
		// fandom-end
	}

	WebHook struct {
		deps webHookDependencies
		conf json.RawMessage
	}

	detailedMessage struct {
		ID      int
		Text    string
		Type    string
		Context json.RawMessage `json:"context,omitempty"`
	}

	errorMessage struct {
		InstancePtr      string
		Message          string
		DetailedMessages []detailedMessage
	}

	rawHookResponse struct {
		Messages []errorMessage
	}

	httpConfig struct {
		sum     string
		retries int
		minWait time.Duration
		maxWait time.Duration
		timeout time.Duration
	}
)

func NewWebHook(r webHookDependencies, c json.RawMessage) *WebHook {
	return &WebHook{deps: r, conf: c}
}

func (e *WebHook) ExecuteLoginPreHook(_ http.ResponseWriter, req *http.Request, flow *login.Flow) error {
	ctx, _ := e.deps.Tracer(req.Context()).Tracer().Start(req.Context(), "selfservice.hook.ExecutePreLoginHook")
	return e.execute(ctx, &templateContext{
		Flow:           flow,
		RequestHeaders: req.Header,
		RequestMethod:  req.Method,
		RequestUrl:     req.RequestURI,
		HookType:       "LoginPreHook",
	})
}

func (e *WebHook) ExecuteLoginPostHook(_ http.ResponseWriter, req *http.Request, flow *login.Flow, session *session.Session) error {
	// fandom-start
	if req.Body != nil {
		if err := req.ParseForm(); err != nil {
			return errors.WithStack(err)
		}
	}
	// fandom-end
	ctx, _ := e.deps.Tracer(req.Context()).Tracer().Start(req.Context(), "selfservice.hook.ExecutePostLoginHook")
	return e.execute(ctx, &templateContext{
		Flow:           flow,
		RequestHeaders: req.Header,
		RequestMethod:  req.Method,
		RequestUrl:     req.RequestURI,
		Identity:       session.Identity,
		HookType:       "LoginPostHook",
		// fandom-start
		Fields: req.Form,
		// fandom-end
	})
}

func (e *WebHook) ExecutePostVerificationHook(_ http.ResponseWriter, req *http.Request, flow *verification.Flow, identity *identity.Identity) error {
	ctx, _ := e.deps.Tracer(req.Context()).Tracer().Start(req.Context(), "selfservice.hook.ExecutePostVerificationHook")
	return e.execute(ctx, &templateContext{
		Flow:           flow,
		RequestHeaders: req.Header,
		RequestMethod:  req.Method,
		RequestUrl:     req.RequestURI,
		Identity:       identity,
		HookType:       "LoginPreHook",
	})
}

func (e *WebHook) ExecutePostRecoveryHook(_ http.ResponseWriter, req *http.Request, flow *recovery.Flow, session *session.Session) error {
	ctx, _ := e.deps.Tracer(req.Context()).Tracer().Start(req.Context(), "selfservice.hook.ExecutePostRecoveryHook")
	return e.execute(ctx, &templateContext{
		Flow:           flow,
		RequestHeaders: req.Header,
		RequestMethod:  req.Method,
		RequestUrl:     req.RequestURI,
		Identity:       session.Identity,
		HookType:       "PostRecoveryHook",
	})
}

func (e *WebHook) ExecuteRegistrationPreHook(_ http.ResponseWriter, req *http.Request, flow *registration.Flow) error {
	ctx, _ := e.deps.Tracer(req.Context()).Tracer().Start(req.Context(), "selfservice.hook.ExecuteRegistrationPreHook")
	return e.execute(ctx, &templateContext{
		Flow:           flow,
		RequestHeaders: req.Header,
		RequestMethod:  req.Method,
		RequestUrl:     req.RequestURI,
		HookType:       "RegistrationPreHook",
	})
}

func (e *WebHook) ExecutePostRegistrationPrePersistHook(_ http.ResponseWriter, req *http.Request, flow *registration.Flow, id *identity.Identity, ct identity.CredentialsType) error {
	credentials, _ := id.GetCredentials(ct)
	// fandom-start
	if req.Body != nil {
		if err := req.ParseForm(); err != nil {
			return errors.WithStack(err)
		}
	}
	ctx, _ := e.deps.Tracer(req.Context()).Tracer().Start(req.Context(), "selfservice.hook.ExecutePostRegistrationPrePersistHook")
	// fandom-end
	return e.execute(ctx, &templateContext{
		Flow:           flow,
		RequestHeaders: req.Header,
		RequestMethod:  req.Method,
		RequestUrl:     req.RequestURI,
		Identity:       id,
		// fandom-start
		Credentials: credentials,
		Fields:      req.Form,
		HookType:    "PostRegistrationPrePersistHook:" + ct.String(),
		// fandom-end
	})
}

func (e *WebHook) ExecutePostRegistrationPostPersistHook(_ http.ResponseWriter, req *http.Request, flow *registration.Flow, session *session.Session, ct identity.CredentialsType) error {
	// fandom-start
	credentials, _ := session.Identity.GetCredentials(ct)
	if req.Body != nil {
		if err := req.ParseForm(); err != nil {
			return errors.WithStack(err)
		}
	}
	// fandom-end
	ctx, _ := e.deps.Tracer(req.Context()).Tracer().Start(req.Context(), "selfservice.hook.ExecutePostRegistrationPostPersistHook")
	return e.execute(ctx, &templateContext{
		Flow:           flow,
		RequestHeaders: req.Header,
		RequestMethod:  req.Method,
		RequestUrl:     req.RequestURI,
		Identity:       session.Identity,
		// fandom-start
		Credentials: credentials,
		Fields:      req.Form,
		HookType:    "PostRegistrationPostPersistHook:" + ct.String(),
		// fandom-end
	})
}

// fandom-start

func (e *WebHook) ExecuteSettingsPrePersistHook(_ http.ResponseWriter, req *http.Request, flow *settings.Flow, id *identity.Identity, settingsType string) error {
	var credentials *identity.Credentials
	if settingsType == "password" {
		credentials, _ = id.GetCredentials(identity.CredentialsTypePassword)
	} else if settingsType == "oidc" {
		credentials, _ = id.GetCredentials(identity.CredentialsTypeOIDC)
	}
	ctx, _ := e.deps.Tracer(req.Context()).Tracer().Start(req.Context(), "selfservice.hook.ExecuteSettingsPostPersistHook")
	return e.execute(ctx, &templateContext{
		Flow:           flow,
		RequestHeaders: req.Header,
		RequestMethod:  req.Method,
		RequestUrl:     req.RequestURI,
		Identity:       id,
		Credentials:    credentials,
		HookType:       "SettingsPrePersistHook:" + settingsType,
	})
}

func newHttpConfig(r json.RawMessage) (*httpConfig, error) {
	type rawHttpConfig struct {
		Retries int
		Timeout string
		MinWait string `json:"min_wait"`
		MaxWait string `json:"max_wait"`
	}
	var rc rawHttpConfig
	err := json.Unmarshal(r, &rc)
	if err != nil {
		return nil, err
	}

	timeout := time.Minute
	retryWaitMin := 1 * time.Second
	retryWaitMax := 30 * time.Second
	retryMax := 4
	if t, err := time.ParseDuration(rc.Timeout); err != nil {
		timeout = t
	}
	if t, err := time.ParseDuration(rc.MinWait); err != nil {
		retryWaitMin = t
	}
	if t, err := time.ParseDuration(rc.MaxWait); err != nil {
		retryWaitMin = t
	}
	if rc.Retries > 0 {
		retryMax = rc.Retries
	}

	return &httpConfig{
		sum:     fmt.Sprintf("%x", md5.Sum(r)), //nolint:gosec
		retries: retryMax,
		timeout: timeout,
		minWait: retryWaitMin,
		maxWait: retryWaitMax,
	}, nil
}

// fandom-end

func (e *WebHook) ExecuteSettingsPostPersistHook(_ http.ResponseWriter, req *http.Request, flow *settings.Flow, id *identity.Identity, settingsType string) error {
	// fandom-start
	var credentials *identity.Credentials
	if settingsType == "password" {
		credentials, _ = id.GetCredentials(identity.CredentialsTypePassword)
	} else if settingsType == "oidc" {
		credentials, _ = id.GetCredentials(identity.CredentialsTypeOIDC)
	}
	// fandom-end
	ctx, _ := e.deps.Tracer(req.Context()).Tracer().Start(req.Context(), "selfservice.hook.ExecuteSettingsPostPersistHook")
	return e.execute(ctx, &templateContext{
		Flow:           flow,
		RequestHeaders: req.Header,
		RequestMethod:  req.Method,
		RequestUrl:     req.RequestURI,
		Identity:       id,
		// fandom-start
		Credentials: credentials,
		HookType:    "SettingsPostPersistHook:" + settingsType,
		// fandom-end
	})
}

func (e *WebHook) execute(ctx context.Context, data *templateContext) error {
	span := trace.SpanFromContext(ctx)
	attrs := map[string]string{
		"webhook.http.method":  data.RequestMethod,
		"webhook.http.url":     data.RequestUrl,
		"webhook.http.headers": fmt.Sprintf("%#v", data.RequestHeaders),
		"webhook.identity":     fmt.Sprintf("%#v", data.Identity),
	}
	span.SetAttributes(otelx.StringAttrs(attrs)...)
	defer span.End()
	conf, err := newHttpConfig(e.conf)
	if err != nil {
		return fmt.Errorf("failed to parse http config: %w", err)
	}

	client := e.deps.NamedHTTPClient(
		ctx,
		data.HookType+conf.sum,
		httpx.ResilientClientWithMaxRetry(conf.retries),
		httpx.ResilientClientWithConnectionTimeout(conf.timeout),
		httpx.ResilientClientWithMinxRetryWait(conf.minWait),
		httpx.ResilientClientWithMaxRetryWait(conf.maxWait),
	)
	builder, err := request.NewBuilder(e.conf, client, e.deps.Logger())
	if err != nil {
		return err
	}

	req, err := builder.BuildRequest(data)
	if errors.Is(err, request.ErrCancel) {
		return nil
	} else if err != nil {
		return err
	}

	errChan := make(chan error, 1)
	go func(client *retryablehttp.Client) {
		defer close(errChan)

		resp, err := client.Do(req)
		if err != nil {
			errChan <- err
			return
		}

		if resp.StatusCode >= http.StatusBadRequest {
			errChan <- e.parseResponse(resp)
			span.SetStatus(codes.Error, fmt.Sprintf("web hook failed with status code %v", resp.StatusCode))
			return
		}

		errChan <- nil
	}(client)

	if gjson.GetBytes(e.conf, "response.ignore").Bool() {
		go func() {
			err := <-errChan
			e.deps.Logger().WithError(err).Warning("A web hook request failed but the error was ignored because the configuration indicated that the upstream response should be ignored.")
		}()
		return nil
	}

	return <-errChan
}

func (e *WebHook) parseResponse(resp *http.Response) (err error) {
	if resp == nil {
		return fmt.Errorf("empty response provided from the webhook")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "could not read response body")
	}

	hookResponse := &rawHookResponse{
		Messages: []errorMessage{},
	}

	// fandom-start
	e.deps.Logger().WithField("response", string(body)).WithField("status_code", resp.StatusCode).Debug("webhook: received response")
	// fandom-end

	if err = json.Unmarshal(body, &hookResponse); err != nil {
		return errors.Wrap(err, "hook response could not be unmarshalled properly")
	}

	validationErr := schema.NewValidationListError()
	for _, msg := range hookResponse.Messages {
		messages := text.Messages{}
		for _, detail := range msg.DetailedMessages {
			messages.Add(&text.Message{
				ID:      text.ID(detail.ID),
				Text:    detail.Text,
				Type:    text.Type(detail.Type),
				Context: detail.Context,
			})
		}
		validationErr.Add(schema.NewHookValidationError(msg.InstancePtr, msg.Message, messages))
	}

	if !validationErr.HasErrors() {
		// fandom-start
		e.deps.Logger().WithField("validations", validationErr).Debug("webhook: parsed validations")
		// fandom-end
		return errors.New("error while parsing hook response: got no validation errors")
	}

	return errors.WithStack(validationErr)
}
