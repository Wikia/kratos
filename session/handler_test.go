package session_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/kratos/corpx"
	"github.com/ory/kratos/identity"
	"github.com/ory/x/sqlcon"

	"github.com/julienschmidt/httprouter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/internal/testhelpers"
	. "github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
	"github.com/ory/x/urlx"
)

func init() {
	corpx.RegisterFakes()
}

func send(code int) httprouter.Handle {
	return func(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
		w.WriteHeader(code)
	}
}

func TestSessionWhoAmI(t *testing.T) {
	t.Run("public", func(t *testing.T) {
		conf, reg := internal.NewFastRegistryWithMocks(t)
		r := x.NewRouterPublic()

		// set this intermediate because kratos needs some valid url for CRUDE operations
		conf.MustSet(config.ViperKeyPublicBaseURL, "http://example.com")
		h, _ := testhelpers.MockSessionCreateHandler(t, reg)
		r.GET("/set", h)

		NewHandler(reg).RegisterPublicRoutes(r)
		ts := httptest.NewServer(r)
		defer ts.Close()

		conf.MustSet(config.ViperKeyPublicBaseURL, ts.URL)
		client := testhelpers.NewClientWithCookies(t)

		// No cookie yet -> 401
		res, err := client.Get(ts.URL + RouteWhoami)
		require.NoError(t, err)
		assert.EqualValues(t, http.StatusUnauthorized, res.StatusCode)

		// Set cookie
		testhelpers.MockHydrateCookieClient(t, client, ts.URL+"/set")

		// Cookie set -> 200 (GET)
		for _, method := range []string{
			"GET",
			"POST",
			"PUT",
			"DELETE",
		} {
			t.Run("http_method="+method, func(t *testing.T) {
				req, err := http.NewRequest(method, ts.URL+RouteWhoami, nil)
				require.NoError(t, err)

				res, err = client.Do(req)
				require.NoError(t, err)
				assert.EqualValues(t, http.StatusOK, res.StatusCode)
				assert.NotEmpty(t, res.Header.Get("X-Kratos-Authenticated-Identity-Id"))
			})
		}
	})
}

func TestIsNotAuthenticatedSecurecookie(t *testing.T) {
	conf, reg := internal.NewFastRegistryWithMocks(t)
	r := x.NewRouterPublic()
	r.GET("/public/with-callback", reg.SessionHandler().IsNotAuthenticated(send(http.StatusOK), send(http.StatusBadRequest)))

	ts := httptest.NewServer(r)
	defer ts.Close()
	conf.MustSet(config.ViperKeyPublicBaseURL, ts.URL)

	c := testhelpers.NewClientWithCookies(t)
	c.Jar.SetCookies(urlx.ParseOrPanic(ts.URL), []*http.Cookie{
		{
			Name: config.DefaultSessionCookieName,
			// This is an invalid cookie because it is generated by a very random secret
			Value:    "MTU3Mjg4Njg0MXxEdi1CQkFFQ180SUFBUkFCRUFBQU52LUNBQUVHYzNSeWFXNW5EQVVBQTNOcFpBWnpkSEpwYm1jTUd3QVpUWFZXVUhSQlZVeExXRWRUUmxkVVoyUkpUVXhzY201SFNBPT187kdI3dMP-ep389egDR2TajYXGG-6xqC2mAlgnBi0vsg=",
			HttpOnly: true,
			Path:     "/",
			Expires:  time.Now().Add(time.Hour),
		},
	})

	res, err := c.Get(ts.URL + "/public/with-callback")
	require.NoError(t, err)

	assert.EqualValues(t, http.StatusOK, res.StatusCode)
}

func TestIsNotAuthenticated(t *testing.T) {
	conf, reg := internal.NewFastRegistryWithMocks(t)
	r := x.NewRouterPublic()
	// set this intermediate because kratos needs some valid url for CRUDE operations
	conf.MustSet(config.ViperKeyPublicBaseURL, "http://example.com")

	reg.WithCSRFHandler(new(x.FakeCSRFHandler))
	h, _ := testhelpers.MockSessionCreateHandler(t, reg)
	r.GET("/set", h)
	r.GET("/public/with-callback", reg.SessionHandler().IsNotAuthenticated(send(http.StatusOK), send(http.StatusBadRequest)))
	r.GET("/public/without-callback", reg.SessionHandler().IsNotAuthenticated(send(http.StatusOK), nil))
	ts := httptest.NewServer(r)
	defer ts.Close()

	conf.MustSet(config.ViperKeyPublicBaseURL, ts.URL)

	sessionClient := testhelpers.NewClientWithCookies(t)
	testhelpers.MockHydrateCookieClient(t, sessionClient, ts.URL+"/set")

	for k, tc := range []struct {
		c    *http.Client
		call string
		code int
	}{
		{
			c:    sessionClient,
			call: "/public/with-callback",
			code: http.StatusBadRequest,
		},
		{
			c:    http.DefaultClient,
			call: "/public/with-callback",
			code: http.StatusOK,
		},

		{
			c:    sessionClient,
			call: "/public/without-callback",
			code: http.StatusForbidden,
		},
		{
			c:    http.DefaultClient,
			call: "/public/without-callback",
			code: http.StatusOK,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			res, err := tc.c.Get(ts.URL + tc.call)
			require.NoError(t, err)

			assert.EqualValues(t, tc.code, res.StatusCode)
		})
	}
}

func TestIsAuthenticated(t *testing.T) {
	conf, reg := internal.NewFastRegistryWithMocks(t)
	reg.WithCSRFHandler(new(x.FakeCSRFHandler))
	r := x.NewRouterPublic()

	h, _ := testhelpers.MockSessionCreateHandler(t, reg)
	r.GET("/set", h)
	r.GET("/privileged/with-callback", reg.SessionHandler().IsAuthenticated(send(http.StatusOK), send(http.StatusBadRequest)))
	r.GET("/privileged/without-callback", reg.SessionHandler().IsAuthenticated(send(http.StatusOK), nil))
	ts := httptest.NewServer(r)
	defer ts.Close()
	conf.MustSet(config.ViperKeyPublicBaseURL, ts.URL)

	sessionClient := testhelpers.NewClientWithCookies(t)
	testhelpers.MockHydrateCookieClient(t, sessionClient, ts.URL+"/set")

	for k, tc := range []struct {
		c    *http.Client
		call string
		code int
	}{
		{
			c:    sessionClient,
			call: "/privileged/with-callback",
			code: http.StatusOK,
		},
		{
			c:    http.DefaultClient,
			call: "/privileged/with-callback",
			code: http.StatusBadRequest,
		},

		{
			c:    sessionClient,
			call: "/privileged/without-callback",
			code: http.StatusOK,
		},
		{
			c:    http.DefaultClient,
			call: "/privileged/without-callback",
			code: http.StatusForbidden,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			res, err := tc.c.Get(ts.URL + tc.call)
			require.NoError(t, err)

			assert.EqualValues(t, tc.code, res.StatusCode)
		})
	}
}

func TestSessionLogout(t *testing.T) {
	conf, reg := internal.NewFastRegistryWithMocks(t)

	// Start kratos server
	publicTS, adminTS := testhelpers.NewKratosServerWithCSRF(t, reg)

	mockServerURL := urlx.ParseOrPanic(publicTS.URL)

	conf.MustSet(config.ViperKeyAdminBaseURL, adminTS.URL)
	testhelpers.SetDefaultIdentitySchema(t, conf, "file://./stub/identity.schema.json")
	testhelpers.SetIdentitySchemas(t, conf, map[string]string{
		"customer": "file://./stub/handler/customer.schema.json",
		"employee": "file://./stub/handler/employee.schema.json",
	})
	conf.MustSet(config.ViperKeyPublicBaseURL, mockServerURL.String())

	var logout = func(t *testing.T, base *httptest.Server, href string, expectCode int) {
		req, err := http.NewRequest("DELETE", base.URL+href, nil)
		require.NoError(t, err)

		res, err := base.Client().Do(req)
		require.NoError(t, err)

		require.EqualValues(t, expectCode, res.StatusCode)
	}

	t.Run("case=should return 202 after invalidating all sessions", func(t *testing.T) {
		for name, ts := range map[string]*httptest.Server{"public": publicTS, "admin": adminTS} {
			t.Run("endpoint="+name, func(t *testing.T) {
				i := identity.NewIdentity("")
				require.NoError(t, reg.IdentityManager().Create(context.Background(), i))
				s := &Session{Identity: i}
				require.NoError(t, reg.SessionPersister().CreateSession(context.Background(), s))

				logout(t, ts, "/sessions/identity/"+i.ID.String(), http.StatusAccepted)
				_, err := reg.SessionPersister().GetSession(context.Background(), s.ID)
				require.True(t, errors.Is(err, sqlcon.ErrNoRows))
			})
		}
	})
}

func TestSessionRequest(t *testing.T) {
	conf, reg := internal.NewFastRegistryWithMocks(t)

	// Start kratos server
	publicTS, adminTS := testhelpers.NewKratosServerWithCSRF(t, reg)

	mockServerURL := urlx.ParseOrPanic(publicTS.URL)

	conf.MustSet(config.ViperKeyAdminBaseURL, adminTS.URL)
	testhelpers.SetDefaultIdentitySchema(t, conf, "file://./stub/identity.schema.json")
	testhelpers.SetIdentitySchemas(t, conf, map[string]string{
		"customer": "file://./stub/handler/customer.schema.json",
		"employee": "file://./stub/handler/employee.schema.json",
	})
	conf.MustSet(config.ViperKeyPublicBaseURL, mockServerURL.String())

	session := func(t *testing.T, base *httptest.Server, href string, expectCode int) AdminIdentitySessionResponse {
		req, err := http.NewRequest("GET", base.URL+href, nil)
		require.NoError(t, err)

		res, err := base.Client().Do(req)
		require.NoError(t, err)

		require.EqualValues(t, expectCode, res.StatusCode)
		defer res.Body.Close()

		var apiRes AdminIdentitySessionResponse
		err = json.NewDecoder(res.Body).Decode(&apiRes)
		require.NoError(t, err)
		require.Contains(t, res.Header.Get("set-cookie"), config.DefaultSessionCookieName)

		return apiRes
	}

	t.Run("case=should return 200 after successful session creation and return valid session and token", func(t *testing.T) {
		for name, ts := range map[string]*httptest.Server{"public": publicTS, "admin": adminTS} {
			t.Run("endpoint="+name, func(t *testing.T) {
				i := identity.NewIdentity("")
				require.NoError(t, reg.IdentityManager().Create(context.Background(), i))

				res := session(t, ts, "/sessions/identity/"+i.ID.String(), http.StatusOK)
				s, err := reg.SessionPersister().GetSession(context.Background(), res.Session.ID)
				require.Empty(t, err)
				require.Equal(t, i.ID.String(), s.Identity.ID.String())
				require.Equal(t, s.Token, res.Token)
				require.True(t, s.Active)
			})
		}
	})
}
