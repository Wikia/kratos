// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

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

	"github.com/ory/herodot"

	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.11.0"
	"go.opentelemetry.io/otel/trace"
	grpccodes "google.golang.org/grpc/codes"

	"github.com/ory/kratos/ui/node"
	"github.com/ory/x/httpx"
	"github.com/ory/x/jsonnetsecure"
	"github.com/ory/x/otelx"

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
)

var (
	_ registration.PostHookPostPersistExecutor = new(WebHook)
	_ registration.PostHookPrePersistExecutor  = new(WebHook)

	_ verification.PostHookExecutor = new(WebHook)

	_ recovery.PostHookExecutor = new(WebHook)

	_ settings.PostHookPostPersistExecutor = new(WebHook)
	_ settings.PostHookPrePersistExecutor  = new(WebHook)
)

type (
	webHookDependencies interface {
		x.LoggingProvider
		x.HTTPClientProvider
		x.TracingProvider
		jsonnetsecure.VMProvider
		x.ResilientClientProvider
	}

	templateContext struct {
		Flow           flow.Flow          `json:"flow"`
		RequestHeaders http.Header        `json:"request_headers"`
		RequestMethod  string             `json:"request_method"`
		RequestURL     string             `json:"request_url"`
		RequestCookies map[string]string  `json:"request_cookies"`
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
		ID      int             `json:"id"`
		Text    string          `json:"text"`
		Type    string          `json:"type"`
		Context json.RawMessage `json:"context,omitempty"`
	}

	errorMessage struct {
		InstancePtr      string            `json:"instance_ptr"`
		Message          string            `json:"message,omitempty"`
		DetailedMessages []detailedMessage `json:"messages"`
	}

	rawHookResponse struct {
		Messages []errorMessage `json:"messages"`
	}

	httpConfig struct {
		sum     string
		retries int
		minWait time.Duration
		maxWait time.Duration
		timeout time.Duration
	}
)

func cookies(req *http.Request) map[string]string {
	cookies := make(map[string]string)
	for _, c := range req.Cookies() {
		if c.Name != "" {
			cookies[c.Name] = c.Value
		}
	}
	return cookies
}

func NewWebHook(r webHookDependencies, c json.RawMessage) *WebHook {
	return &WebHook{deps: r, conf: c}
}

func (e *WebHook) ExecuteLoginPreHook(_ http.ResponseWriter, req *http.Request, flow *login.Flow) error {
	return otelx.WithSpan(req.Context(), "selfservice.hook.WebHook.ExecuteLoginPreHook", func(ctx context.Context) error {
		return e.execute(ctx, &templateContext{
			Flow:           flow,
			RequestHeaders: req.Header,
			RequestMethod:  req.Method,
			RequestURL:     x.RequestURL(req).String(),
			RequestCookies: cookies(req),
			HookType:       "LoginPreHook",
		})
	})
}

func (e *WebHook) ExecuteLoginPostHook(_ http.ResponseWriter, req *http.Request, _ node.UiNodeGroup, flow *login.Flow, session *session.Session) error {
	// fandom-start
	if req.Body != nil {
		if err := req.ParseForm(); err != nil {
			return errors.WithStack(err)
		}
	}
	// fandom-end

	return otelx.WithSpan(req.Context(), "selfservice.hook.WebHook.ExecuteLoginPostHook", func(ctx context.Context) error {
		return e.execute(ctx, &templateContext{
			Flow:           flow,
			RequestHeaders: req.Header,
			RequestMethod:  req.Method,
			RequestURL:     x.RequestURL(req).String(),
			RequestCookies: cookies(req),
			Identity:       session.Identity,
			HookType:       "LoginPostHook",
			Fields:         req.Form,
		})
	})
}

func (e *WebHook) ExecuteVerificationPreHook(_ http.ResponseWriter, req *http.Request, flow *verification.Flow) error {
	return otelx.WithSpan(req.Context(), "selfservice.hook.WebHook.ExecuteVerificationPreHook", func(ctx context.Context) error {
		return e.execute(ctx, &templateContext{
			Flow:           flow,
			RequestHeaders: req.Header,
			RequestMethod:  req.Method,
			RequestURL:     x.RequestURL(req).String(),
			RequestCookies: cookies(req),
			HookType:       "VerificationPreHook",
		})
	})
}

func (e *WebHook) ExecutePostVerificationHook(_ http.ResponseWriter, req *http.Request, flow *verification.Flow, id *identity.Identity) error {
	return otelx.WithSpan(req.Context(), "selfservice.hook.WebHook.ExecutePostVerificationHook", func(ctx context.Context) error {
		return e.execute(ctx, &templateContext{
			Flow:           flow,
			RequestHeaders: req.Header,
			RequestMethod:  req.Method,
			RequestURL:     x.RequestURL(req).String(),
			RequestCookies: cookies(req),
			Identity:       id,
			HookType:       "VerificationPostHook",
		})
	})
}

func (e *WebHook) ExecuteRecoveryPreHook(_ http.ResponseWriter, req *http.Request, flow *recovery.Flow) error {
	return otelx.WithSpan(req.Context(), "selfservice.hook.WebHook.ExecuteRecoveryPreHook", func(ctx context.Context) error {
		return e.execute(ctx, &templateContext{
			Flow:           flow,
			RequestHeaders: req.Header,
			RequestMethod:  req.Method,
			RequestCookies: cookies(req),
			RequestURL:     x.RequestURL(req).String(),
			HookType:       "RecoveryPreHook",
		})
	})
}

func (e *WebHook) ExecutePostRecoveryHook(_ http.ResponseWriter, req *http.Request, flow *recovery.Flow, session *session.Session) error {
	return otelx.WithSpan(req.Context(), "selfservice.hook.WebHook.ExecutePostRecoveryHook", func(ctx context.Context) error {
		return e.execute(ctx, &templateContext{
			Flow:           flow,
			RequestHeaders: req.Header,
			RequestMethod:  req.Method,
			RequestURL:     x.RequestURL(req).String(),
			RequestCookies: cookies(req),
			Identity:       session.Identity,
			HookType:       "RecoveryPostHook",
		})
	})
}

func (e *WebHook) ExecuteRegistrationPreHook(_ http.ResponseWriter, req *http.Request, flow *registration.Flow) error {
	return otelx.WithSpan(req.Context(), "selfservice.hook.WebHook.ExecuteRegistrationPreHook", func(ctx context.Context) error {
		return e.execute(ctx, &templateContext{
			Flow:           flow,
			RequestHeaders: req.Header,
			RequestMethod:  req.Method,
			RequestURL:     x.RequestURL(req).String(),
			RequestCookies: cookies(req),
			HookType:       "RegistrationPreHook",
		})
	})
}

func (e *WebHook) ExecutePostRegistrationPrePersistHook(_ http.ResponseWriter, req *http.Request, flow *registration.Flow, id *identity.Identity, ct identity.CredentialsType) error {
	if !(gjson.GetBytes(e.conf, "can_interrupt").Bool() || gjson.GetBytes(e.conf, "response.parse").Bool()) {
		return nil
	}
	// fandom-start
	credentials, _ := id.GetCredentials(ct)
	if req.Body != nil {
		if err := req.ParseForm(); err != nil {
			return errors.WithStack(err)
		}
	}
	// fandom-end
	return otelx.WithSpan(req.Context(), "selfservice.hook.WebHook.ExecutePostRegistrationPrePersistHook", func(ctx context.Context) error {
		return e.execute(ctx, &templateContext{
			Flow:           flow,
			RequestHeaders: req.Header,
			RequestMethod:  req.Method,
			RequestURL:     x.RequestURL(req).String(),
			RequestCookies: cookies(req),
			Identity:       id,
			// fandom-start
			Credentials: credentials,
			Fields:      req.Form,
			HookType:    "PostRegistrationPrePersistHook:" + ct.String(),
			// fandom-end
		})
	})
}

func (e *WebHook) ExecutePostRegistrationPostPersistHook(_ http.ResponseWriter, req *http.Request, flow *registration.Flow, session *session.Session, ct identity.CredentialsType) error {
	if gjson.GetBytes(e.conf, "can_interrupt").Bool() || gjson.GetBytes(e.conf, "response.parse").Bool() {
		return nil
	}
	// fandom-start
	credentials, _ := session.Identity.GetCredentials(ct)
	if req.Body != nil {
		if err := req.ParseForm(); err != nil {
			return errors.WithStack(err)
		}
	}
	// fandom-end

	// We want to decouple the request from the hook execution, so that the hooks still execute even
	// if the request is canceled.
	var cancel context.CancelFunc
	ctx := trace.ContextWithSpan(context.Background(), trace.SpanFromContext(req.Context()))
	ctx, cancel = context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	return otelx.WithSpan(ctx, "selfservice.hook.WebHook.ExecutePostRegistrationPostPersistHook", func(ctx context.Context) error {
		return e.execute(ctx, &templateContext{
			Flow:           flow,
			RequestHeaders: req.Header,
			RequestMethod:  req.Method,
			RequestURL:     x.RequestURL(req).String(),
			RequestCookies: cookies(req),
			Identity:       session.Identity,
			// fandom-start
			Credentials: credentials,
			Fields:      req.Form,
			HookType:    "PostRegistrationPostPersistHook:" + ct.String(),
			// fandom-end
		})
	})
}

// fandom-start

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

func (e *WebHook) ExecuteSettingsPreHook(_ http.ResponseWriter, req *http.Request, flow *settings.Flow) error {
	return otelx.WithSpan(req.Context(), "selfservice.hook.WebHook.ExecuteSettingsPreHook", func(ctx context.Context) error {
		return e.execute(ctx, &templateContext{
			Flow:           flow,
			RequestHeaders: req.Header,
			RequestMethod:  req.Method,
			RequestURL:     x.RequestURL(req).String(),
			RequestCookies: cookies(req),
			HookType:       "SettingsPreHook",
		})
	})
}

func (e *WebHook) ExecuteSettingsPostPersistHook(_ http.ResponseWriter, req *http.Request, flow *settings.Flow, id *identity.Identity, settingsType string) error {
	if gjson.GetBytes(e.conf, "can_interrupt").Bool() || gjson.GetBytes(e.conf, "response.parse").Bool() {
		return nil
	}
	// fandom-start
	var credentials *identity.Credentials
	if settingsType == "password" {
		credentials, _ = id.GetCredentials(identity.CredentialsTypePassword)
	} else if settingsType == "oidc" {
		credentials, _ = id.GetCredentials(identity.CredentialsTypeOIDC)
	}
	// fandom-end
	return otelx.WithSpan(req.Context(), "selfservice.hook.WebHook.ExecuteSettingsPostPersistHook", func(ctx context.Context) error {
		return e.execute(ctx, &templateContext{
			Flow:           flow,
			RequestHeaders: req.Header,
			RequestMethod:  req.Method,
			RequestURL:     x.RequestURL(req).String(),
			RequestCookies: cookies(req),
			Identity:       id,
			Credentials:    credentials,
			HookType:       "SettingsPostPersistHook",
		})
	})
}

func (e *WebHook) ExecuteSettingsPrePersistHook(_ http.ResponseWriter, req *http.Request, flow *settings.Flow, id *identity.Identity, settingsType string) error {
	if !(gjson.GetBytes(e.conf, "can_interrupt").Bool() || gjson.GetBytes(e.conf, "response.parse").Bool()) {
		return nil
	}

	// fandom-start
	var credentials *identity.Credentials
	if settingsType == "password" {
		credentials, _ = id.GetCredentials(identity.CredentialsTypePassword)
	} else if settingsType == "oidc" {
		credentials, _ = id.GetCredentials(identity.CredentialsTypeOIDC)
	}
	// fandom-end

	return otelx.WithSpan(req.Context(), "selfservice.hook.WebHook.ExecuteSettingsPrePersistHook", func(ctx context.Context) error {
		return e.execute(ctx, &templateContext{
			Flow:           flow,
			RequestHeaders: req.Header,
			RequestMethod:  req.Method,
			RequestURL:     x.RequestURL(req).String(),
			RequestCookies: cookies(req),
			Identity:       id,
			// fandom-start
			Credentials: credentials,
			HookType:    "SettingsPostPersistHook:" + settingsType,
			// fandom-end
		})
	})
}

func (e *WebHook) execute(ctx context.Context, data *templateContext) error {
	conf, err := newHttpConfig(e.conf)
	if err != nil {
		return fmt.Errorf("failed to parse http config: %w", err)
	}
	var (
		httpClient = e.deps.NamedHTTPClient(
			ctx,
			data.HookType+conf.sum,
			httpx.ResilientClientWithMaxRetry(conf.retries),
			httpx.ResilientClientWithConnectionTimeout(conf.timeout),
			httpx.ResilientClientWithMinxRetryWait(conf.minWait),
			httpx.ResilientClientWithMaxRetryWait(conf.maxWait),
		)
		ignoreResponse = gjson.GetBytes(e.conf, "response.ignore").Bool()
		canInterrupt   = gjson.GetBytes(e.conf, "can_interrupt").Bool()
		parseResponse  = gjson.GetBytes(e.conf, "response.parse").Bool()
		tracer         = trace.SpanFromContext(ctx).TracerProvider().Tracer("kratos-webhooks")
	)
	if ignoreResponse && (parseResponse || canInterrupt) {
		return errors.WithStack(herodot.ErrInternalServerError.WithReasonf("A webhook is configured to ignore the response but also to parse the response. This is not possible."))
	}

	makeRequest := func() (finalErr error) {
		if ignoreResponse {
			// This is one of the few places where spawning a context.Background() is ok. We need to do this
			// because the function runs asynchronously and we don't want to cancel the request if the
			// incoming request context is cancelled.
			//
			// The webhook will still cancel after 30 seconds as that is the configured timeout for the HTTP client.
			var cancel context.CancelFunc
			ctx = trace.ContextWithSpan(context.Background(), trace.SpanFromContext(ctx))
			ctx, cancel = context.WithTimeout(ctx, 5*time.Minute)
			defer cancel()
		}
		ctx, span := tracer.Start(ctx, "selfservice.webhook")
		defer otelx.End(span, &finalErr)
		startTime := time.Now()

		defer func() {
			traceID, spanID := span.SpanContext().TraceID(), span.SpanContext().SpanID()
			logger := e.deps.Logger().WithField("otel", map[string]string{
				"trace_id": traceID.String(),
				"span_id":  spanID.String(),
			}).WithField("duration", time.Since(startTime))
			if finalErr != nil {
				if ignoreResponse {
					logger.WithError(finalErr).Warning("Webhook request failed but the error was ignored because the configuration indicated that the upstream response should be ignored")
				} else {
					logger.WithError(finalErr).Error("Webhook request failed")
				}
			} else {
				logger.Info("Webhook request succeeded")
			}
		}()

		builder, err := request.NewBuilder(e.conf, e.deps)
		if err != nil {
			return err
		}

		span.SetAttributes(
			attribute.String("webhook.jsonnet.template-uri", builder.Config.TemplateURI),
			attribute.Bool("webhook.can_interrupt", canInterrupt),
			attribute.Bool("webhook.response.ignore", ignoreResponse),
			attribute.Bool("webhook.response.parse", parseResponse),
		)

		req, err := builder.BuildRequest(ctx, data)
		if errors.Is(err, request.ErrCancel) {
			span.SetAttributes(attribute.Bool("webhook.jsonnet.canceled", true))
			return nil
		} else if err != nil {
			return err
		}

		if data.Identity != nil {
			span.SetAttributes(
				attribute.String("webhook.identity.id", data.Identity.ID.String()),
				attribute.String("webhook.identity.nid", data.Identity.NID.String()),
			)
		}

		e.deps.Logger().WithRequest(req.Request).Info("Dispatching webhook")

		req = req.WithContext(ctx)

		resp, err := httpClient.Do(req)
		if err != nil {
			if isTimeoutError(err) {
				return herodot.DefaultError{
					CodeField:     http.StatusGatewayTimeout,
					StatusField:   http.StatusText(http.StatusGatewayTimeout),
					GRPCCodeField: grpccodes.DeadlineExceeded,
					ErrorField:    err.Error(),
					ReasonField:   "A third-party upstream service could not be reached. Please try again later.",
				}.WithWrap(errors.WithStack(err))
			}
			return errors.WithStack(err)
		}
		defer resp.Body.Close()
		span.SetAttributes(semconv.HTTPAttributesFromHTTPStatusCode(resp.StatusCode)...)

		if resp.StatusCode >= http.StatusBadRequest {
			span.SetStatus(codes.Error, "HTTP status code >= 400")
			if canInterrupt || parseResponse {
				// TODO: double-check if we could use upstream `parseWebhookResponse`
				if err := e.parseResponse(resp); err != nil {
					return err
				}
			}
			return herodot.DefaultError{
				CodeField:     http.StatusBadGateway,
				StatusField:   http.StatusText(http.StatusBadGateway),
				GRPCCodeField: grpccodes.Aborted,
				ReasonField:   "A third-party upstream service responded improperly. Please try again later.",
				ErrorField:    fmt.Sprintf("webhook failed with status code %v", resp.StatusCode),
			}
		}

		if parseResponse {
			// TODO: double-check if we could use upstream `parseWebhookResponse`
			return e.parseResponse(resp)
		}
		return nil
	}

	if !ignoreResponse {
		return makeRequest()
	}
	go func() {
		// we cannot handle the error as we are running async, and it is logged anyway
		_ = makeRequest()
	}()
	return nil
}

func parseWebhookResponse(resp *http.Response, id *identity.Identity) (err error) {
	if resp == nil {
		return errors.Errorf("empty response provided from the webhook")
	}

	if resp.StatusCode == http.StatusOK {
		var hookResponse struct {
			Identity *identity.Identity `json:"identity"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&hookResponse); err != nil {
			return errors.Wrap(err, "webhook response could not be unmarshalled properly from JSON")
		}

		if hookResponse.Identity == nil {
			return nil
		}

		if len(hookResponse.Identity.Traits) > 0 {
			id.Traits = hookResponse.Identity.Traits
		}

		if len(hookResponse.Identity.SchemaID) > 0 {
			id.SchemaID = hookResponse.Identity.SchemaID
		}

		if len(hookResponse.Identity.State) > 0 {
			id.State = hookResponse.Identity.State
		}

		if len(hookResponse.Identity.VerifiableAddresses) > 0 {
			id.VerifiableAddresses = hookResponse.Identity.VerifiableAddresses
		}

		if len(hookResponse.Identity.VerifiableAddresses) > 0 {
			id.VerifiableAddresses = hookResponse.Identity.VerifiableAddresses
		}

		if len(hookResponse.Identity.RecoveryAddresses) > 0 {
			id.RecoveryAddresses = hookResponse.Identity.RecoveryAddresses
		}

		if len(hookResponse.Identity.MetadataPublic) > 0 {
			id.MetadataPublic = hookResponse.Identity.MetadataPublic
		}

		if len(hookResponse.Identity.MetadataAdmin) > 0 {
			id.MetadataAdmin = hookResponse.Identity.MetadataAdmin
		}

		return nil
	} else if resp.StatusCode == http.StatusNoContent {
		return nil
	} else if resp.StatusCode >= http.StatusBadRequest {
		var hookResponse rawHookResponse
		if err := json.NewDecoder(resp.Body).Decode(&hookResponse); err != nil {
			return errors.Wrap(err, "webhook response could not be unmarshalled properly from JSON")
		}

		var validationErrs []*schema.ValidationError
		for _, msg := range hookResponse.Messages {
			messages := text.Messages{}
			for _, detail := range msg.DetailedMessages {
				var msgType text.UITextType
				if detail.Type == "error" {
					msgType = text.Error
				} else {
					msgType = text.Info
				}
				messages.Add(&text.Message{
					ID:      text.ID(detail.ID),
					Text:    detail.Text,
					Type:    msgType,
					Context: detail.Context,
				})
			}
			validationErrs = append(validationErrs, schema.NewHookValidationError(msg.InstancePtr, "a webhook target returned an error", messages))
		}

		if len(validationErrs) == 0 {
			return errors.New("error while parsing webhook response: got no validation errors")
		}

		return schema.NewValidationListError(validationErrs)
	}

	return nil
}

func isTimeoutError(err error) bool {
	var te interface{ Timeout() bool }
	return errors.As(err, &te) && te.Timeout() || errors.Is(err, context.DeadlineExceeded)
}

//nolint:deadcode,unused
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

	var validationErrs []*schema.ValidationError

	for _, msg := range hookResponse.Messages {
		messages := text.Messages{}
		for _, detail := range msg.DetailedMessages {
			messages.Add(&text.Message{
				ID:      text.ID(detail.ID),
				Text:    detail.Text,
				Type:    text.UITextType(detail.Type),
				Context: detail.Context,
			})
		}
		validationErrs = append(validationErrs, schema.NewHookValidationError(msg.InstancePtr, msg.DetailedMessages[0].Text, messages))
	}
	validationErr := schema.NewValidationListError(validationErrs)

	if len(validationErrs) == 0 {
		// fandom-start
		e.deps.Logger().WithField("validations", validationErr).Debug("webhook: parsed validations")
		// fandom-end
		return errors.New("error while parsing hook response: got no validation errors")
	}

	return errors.WithStack(validationErr)
}
