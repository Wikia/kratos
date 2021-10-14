package session

import (
	"net/http"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/pkg/errors"

	"github.com/ory/x/decoderx"

	"github.com/ory/x/errorsx"

	"github.com/ory/herodot"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/x"
)

type (
	handlerDependencies interface {
		identity.PoolProvider
		ManagementProvider
		PersistenceProvider
		x.WriterProvider
		x.LoggingProvider
		x.CSRFProvider
		config.Provider
	}
	HandlerProvider interface {
		SessionHandler() *Handler
	}
	Handler struct {
		r  handlerDependencies
		dx *decoderx.HTTP
	}
)

func NewHandler(
	r handlerDependencies,
) *Handler {
	return &Handler{
		r:  r,
		dx: decoderx.NewHTTP(),
	}
}

const (
	RouteCollection         = "/sessions"
	RouteWhoami             = RouteCollection + "/whoami"
	RouteIdentity           = RouteCollection + "/identity"
	RouteIdentityManagement = RouteIdentity + "/:id"
)

func (h *Handler) RegisterAdminRoutes(admin *x.RouterAdmin) {
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete} {
		// Redirect to public endpoint
		admin.Handle(m, RouteWhoami, x.RedirectToPublicRoute(h.r))
	}

	admin.GET(RouteIdentityManagement, h.session)
	admin.DELETE(RouteIdentityManagement, h.logout)
}

func (h *Handler) RegisterPublicRoutes(public *x.RouterPublic) {
	// We need to completely ignore the whoami path so that we do not accidentally set
	// some cookie.
	h.r.CSRFHandler().IgnorePath(RouteWhoami)
	h.r.CSRFHandler().IgnoreGlob(RouteIdentity + "/*")

	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace} {
		public.Handle(m, RouteWhoami, h.whoami)
		public.Handle(m, RouteIdentityManagement, x.RedirectToAdminRoute(h.r))
	}
}

// nolint:deadcode,unused
// swagger:parameters toSession
type toSession struct {
	// Set the Session Token when calling from non-browser clients. A session token has a format of `MP2YWEMeM8MxjkGKpH4dqOQ4Q4DlSPaj`.
	//
	// in: header
	SessionToken string `json:"X-Session-Token"`

	// Set the Cookie Header. This is especially useful when calling this endpoint from a server-side application. In that
	// scenario you must include the HTTP Cookie Header which originally was included in the request to your server.
	// An example of a session in the HTTP Cookie Header is: `ory_kratos_session=a19iOVAbdzdgl70Rq1QZmrKmcjDtdsviCTZx7m9a9yHIUS8Wa9T7hvqyGTsLHi6Qifn2WUfpAKx9DWp0SJGleIn9vh2YF4A16id93kXFTgIgmwIOvbVAScyrx7yVl6bPZnCx27ec4WQDtaTewC1CpgudeDV2jQQnSaCP6ny3xa8qLH-QUgYqdQuoA_LF1phxgRCUfIrCLQOkolX5nv3ze_f==`.
	//
	// It is ok if more than one cookie are included here as all other cookies will be ignored.
	//
	// in: header
	Cookie string `json:"Cookie"`
}

// swagger:route GET /sessions/whoami v0alpha1 toSession
//
// Check Who the Current HTTP Session Belongs To
//
// Uses the HTTP Headers in the GET request to determine (e.g. by using checking the cookies) who is authenticated.
// Returns a session object in the body or 401 if the credentials are invalid or no credentials were sent.
// Additionally when the request it successful it adds the user ID to the 'X-Kratos-Authenticated-Identity-Id' header in the response.
//
// If you call this endpoint from a server-side application, you must forward the HTTP Cookie Header to this endpoint:
//
//	```js
//	// pseudo-code example
//	router.get('/protected-endpoint', async function (req, res) {
//	  const session = await client.toSession(undefined, req.header('cookie'))
//
//    // console.log(session)
//	})
//	```
//
// When calling this endpoint from a non-browser application (e.g. mobile app) you must include the session token:
//
//	```js
//	// pseudo-code example
//	// ...
//	const session = await client.toSession("the-session-token")
//
//  // console.log(session)
//	```
//
// This endpoint is useful for:
//
// - AJAX calls. Remember to send credentials and set up CORS correctly!
// - Reverse proxies and API Gateways
// - Server-side calls - use the `X-Session-Token` header!
//
// This endpoint authenticates users by checking
//
// - if the `Cookie` HTTP header was set containing an Ory Kratos Session Cookie;
// - if the `Authorization: bearer <ory-session-token>` HTTP header was set with a valid Ory Kratos Session Token;
// - if the `X-Session-Token` HTTP header was set with a valid Ory Kratos Session Token.
//
// If none of these headers are set or the cooke or token are invalid, the endpoint returns a HTTP 401 status code.
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       200: session
//       401: jsonError
//       500: jsonError
func (h *Handler) whoami(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	s, err := h.r.SessionManager().FetchFromRequest(r.Context(), r)
	if err != nil {
		h.r.Audit().WithRequest(r).WithError(err).Info("No valid session cookie found.")
		h.r.Writer().WriteError(w, r, herodot.ErrUnauthorized.WithWrap(err).WithReasonf("No valid session cookie found."))
		return
	}

	// s.Devices = nil
	s.Identity = s.Identity.CopyWithoutCredentials()

	// Set userId as the X-Kratos-Authenticated-Identity-Id header.
	w.Header().Set("X-Kratos-Authenticated-Identity-Id", s.Identity.ID.String())

	h.r.Writer().Write(w, r, s)
}

// swagger:parameters adminLogoutIdentity
// nolint:deadcode,unused
type adminLogoutIdentity struct {
	// ID is the identity's ID.
	//
	// required: true
	// in: path
	ID string `json:"id"`
}

// swagger:route DELETE /sessions/identity/{id} v0alpha1 adminLogoutIdentity
//
// Calling this endpoint irrecoverably and permanently Invalidates all sessions tha belongs to a given Identity.
//
// This endpoint is useful for:
//
// - To forcefully logout Identity from all devices and sessions
//
//     Schemes: http, https
//
//     Security:
//       oryAccessToken:
//
//     Responses:
//       202: emptyResponse
//       401: jsonError
//       500: jsonError
func (h *Handler) logout(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if err := h.r.SessionPersister().DeleteSessionsByIdentity(r.Context(), x.ParseUUID(ps.ByName("id"))); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

// swagger:parameters adminIdentitySession
// nolint:deadcode,unused
type adminIdentitySession struct {
	// ID is the identity's ID.
	//
	// required: true
	// in: path
	ID string `json:"id"`
}

// swagger:model successfulAdminIdentitySession
// nolint:deadcode,unused
type AdminIdentitySessionResponse struct {
	// The Session Token
	//
	// This field is only set when the session hook is configured as a post-registration hook.
	//
	// A session token is equivalent to a session cookie, but it can be sent in the HTTP Authorization
	// Header:
	//
	// 		Authorization: bearer ${session-token}
	//
	// The session token is only issued for API flows, not for Browser flows!
	Token string `json:"session_token"`

	// The Session
	//
	// The session contains information about the user, the session device, and so on.
	//
	// required: true
	Session *Session `json:"session"`

	// The Identity
	//
	// The identity that just signed up.
	//
	// required: true
	Identity *identity.Identity `json:"identity"`
}

// swagger:route GET /sessions/identity/{id} v0alpha1 adminIdentitySession
//
// Calling this endpoint issues a session for a given identity.
//
// This endpoint is useful for:
//
// - Issuing session or session token for a given identity without authenticating
//
//     Schemes: http, https
//
//     Security:
//       oryAccessToken:
//
//     Responses:
//       200: successfulAdminIdentitySession
//       404: jsonError
//       500: jsonError
func (h *Handler) session(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	i, err := h.r.IdentityPool().GetIdentity(r.Context(), x.ParseUUID(ps.ByName("id")))
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	s, err := NewActiveSession(i, h.r.Config(r.Context()), time.Now().UTC())
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	if err := h.r.SessionPersister().CreateSession(r.Context(), s); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	if err := h.r.SessionManager().IssueCookieWithoutCSRF(r.Context(), w, r, s); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	h.r.Writer().Write(w, r, &AdminIdentitySessionResponse{Session: s, Token: s.Token, Identity: i})
}

func (h *Handler) IsAuthenticated(wrap httprouter.Handle, onUnauthenticated httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		if _, err := h.r.SessionManager().FetchFromRequest(r.Context(), r); err != nil {
			if onUnauthenticated != nil {
				onUnauthenticated(w, r, ps)
				return
			}

			h.r.Writer().WriteError(w, r, errors.WithStack(herodot.ErrForbidden.WithReason("This endpoint can only be accessed with a valid session. Please log in and try again.").WithDebugf("%+v", err)))
			return
		}

		wrap(w, r, ps)
	}
}

func (h *Handler) IsNotAuthenticated(wrap httprouter.Handle, onAuthenticated httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		if _, err := h.r.SessionManager().FetchFromRequest(r.Context(), r); err != nil {
			if errorsx.Cause(err).Error() == ErrNoActiveSessionFound.Error() {
				wrap(w, r, ps)
				return
			}
			h.r.Writer().WriteError(w, r, err)
			return
		}

		if onAuthenticated != nil {
			onAuthenticated(w, r, ps)
			return
		}

		h.r.Writer().WriteError(w, r, errors.WithStack(herodot.ErrForbidden.WithReason("This endpoint can only be accessed without a login session. Please log out and try again.")))
	}
}

func RedirectOnAuthenticated(d interface{ config.Provider }) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		returnTo, err := x.SecureRedirectTo(r, d.Config(r.Context()).SelfServiceBrowserDefaultReturnTo(), x.SecureRedirectAllowSelfServiceURLs(d.Config(r.Context()).SelfPublicURL(r)))
		if err != nil {
			http.Redirect(w, r, d.Config(r.Context()).SelfServiceBrowserDefaultReturnTo().String(), http.StatusFound)
			return
		}

		http.Redirect(w, r, returnTo.String(), http.StatusFound)
	}
}

func RedirectOnUnauthenticated(to string) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		http.Redirect(w, r, to, http.StatusFound)
	}
}

func RespondWithJSONErrorOnAuthenticated(h herodot.Writer, err error) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		h.WriteError(w, r, err)
	}
}
