package credentials

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/ory/herodot"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/strategy/oidc"
	"github.com/ory/kratos/selfservice/strategy/password"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/pkg/errors"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/x"

	"github.com/ory/x/jsonx"
)

const RouteItemCredentials = "/identities/:id/credentials"

type (
	handlerDependencies interface {
		identity.PoolProvider
		identity.PrivilegedPoolProvider
		identity.ManagementProvider
		x.WriterProvider
		config.Provider
		x.CSRFProvider
		x.LoggingProvider
	}
	HandlerProvider interface {
		IdentityHandler() *Handler
	}
	Handler struct {
		r handlerDependencies
	}
)

func NewHandler(r handlerDependencies) *Handler {
	return &Handler{r: r}
}

func (h *Handler) RegisterAdminRoutes(admin *x.RouterAdmin) {
	admin.PUT(RouteItemCredentials, h.update)
}

type AdminUpdateIdentityCredentialsBody struct {

	// Credentials to be imported.
	ImportCredentials []ImportCredentialsBody `json:"import_credentials"`
	// Credentials to be removed.
	RemoveCredentials []RemoveCredentialsBody `json:"remove_credentials"`
}

type ImportCredentialsBody struct {
	Type   identity.CredentialsType `json:"type"`
	Config json.RawMessage          `json:"config"`
}

type RemoveCredentialsBody struct {
	Type   identity.CredentialsType `json:"type"`
	Filter string                   `json:"filter"`
}

// swagger:route PUT /identities/{id}/credentials v0alpha1 adminUpdateCredentials
//
// Update Identity Credentials
//
// Calling this endpoint updates the credentials according to the specification provided.
//
// Learn how identities work in [Ory Kratos' User And Identity Model Documentation](https://www.ory.sh/docs/next/kratos/concepts/identity-user-model).
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       204: emptyResponse
//       404: jsonError
//       500: jsonError
func (h *Handler) update(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var ur AdminUpdateIdentityCredentialsBody
	if err := errors.WithStack(jsonx.NewStrictDecoder(r.Body).Decode(&ur)); err != nil {
		h.r.Writer().WriteError(w, r, herodot.ErrBadRequest.WithTrace(err))
		return
	}

	id := x.ParseUUID(ps.ByName("id"))
	i, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), id)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	for _, v := range ur.ImportCredentials {
		creds, ok := i.GetCredentials(v.Type)
		if !ok {
			creds, err = h.createCredentials(r.Context(), id, v)
		} else {
			err = h.updateCredentials(r.Context(), id, creds, v)
		}
		if err != nil {
			h.r.Writer().WriteError(w, r, err)
			return
		}
		i.SetCredentials(v.Type, *creds)
	}

	for _, v := range ur.RemoveCredentials {
		creds, ok := i.GetCredentials(v.Type)
		if ok {
			creds, err := h.removeCredentials(v, creds)
			if err != nil {
				h.r.Writer().WriteError(w, r, err)
				return
			}
			if creds != nil {
				i.SetCredentials(v.Type, *creds)
			} else {
				i.RemoveCredentials(v.Type)
			}
		}
	}

	if err := h.r.IdentityManager().Update(r.Context(), i, identity.ManagerAllowWriteProtectedTraits); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	h.r.Writer().Write(w, r, identity.IdentityWithCredentialsMetadataInJSON(*i))
}

type IdentityAlreadyExists struct {
	identityId uuid.UUID
}

func (e *IdentityAlreadyExists) Error() string {
	return fmt.Sprintf("These OIDC credentials are already used by another identity %s", e.identityId)
}

var ErrUnexpectedProviderType = errors.New("Illegal credentials type")

func (h *Handler) removeCredentials(v RemoveCredentialsBody, creds *identity.Credentials) (*identity.Credentials, error) {
	if v.Type == identity.CredentialsTypeOIDC {
		// oidc may contain more than one entry, so it has to be edited
		var credentialsConfig oidc.CredentialsConfig
		if err := json.Unmarshal(creds.Config, &credentialsConfig); err != nil {
			return nil, err
		}
		var newProviders []oidc.ProviderCredentialsConfig
		var newIds []string
		for _, val := range credentialsConfig.Providers {
			if val.Provider != v.Filter {
				newProviders = append(newProviders, val)
				newIds = append(newIds, credentialsId(val))
			}
		}
		if len(newProviders) == 0 {
			// all OIDCs have been removed - entry should be removed
			return nil, nil
		}
		credentialsConfig.Providers = newProviders
		creds.Identifiers = newIds
		if err := h.replaceConfig(creds, credentialsConfig); err != nil {
			return nil, err
		}
		return creds, nil
	} else if v.Type == identity.CredentialsTypePassword {
		// password can just be removed
		return nil, nil
	} else {
		return nil, errors.WithStack(ErrUnexpectedProviderType)
	}
}

func (h *Handler) createCredentials(ctx context.Context, identityId uuid.UUID, newCreds ImportCredentialsBody) (*identity.Credentials, error) {
	if newCreds.Type == identity.CredentialsTypeOIDC {
		var newConfig oidc.CredentialsConfig
		if err := json.Unmarshal(newCreds.Config, &newConfig); err != nil {
			return nil, err
		}
		var ids []string
		for _, provider := range newConfig.Providers {
			if err := h.doesAnotherIdentityUseTheseOidcCredentials(ctx, identityId, provider); err != nil {
				return nil, err
			}
			ids = append(ids, credentialsId(provider))
		}
		return h.newCredentials(ids, newConfig, newCreds)
	} else if newCreds.Type == identity.CredentialsTypePassword {
		var newConfig password.CredentialsConfig
		if err := json.Unmarshal(newCreds.Config, &newConfig); err != nil {
			return nil, err
		}
		return h.newCredentials([]string{}, newConfig, newCreds)
	} else {
		return nil, errors.WithStack(ErrUnexpectedProviderType)
	}
}

func (h *Handler) newCredentials(ids []string, newConfig interface{}, newCreds ImportCredentialsBody) (*identity.Credentials, error) {
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(newConfig); err != nil {
		return nil, err
	}
	return &identity.Credentials{
		Type:        newCreds.Type,
		Identifiers: ids,
		Config:      b.Bytes(),
	}, nil
}

type OidcCredentialsWithId struct {
	id          string
	credentials oidc.ProviderCredentialsConfig
}

func (h *Handler) updateCredentials(ctx context.Context, identityId uuid.UUID, oldCreds *identity.Credentials, newCreds ImportCredentialsBody) error {
	if newCreds.Type == identity.CredentialsTypeOIDC {
		// for OIDC - replace the ones in the import and leave all the rest w/o changing
		var newConfig oidc.CredentialsConfig
		if err := json.Unmarshal(newCreds.Config, &newConfig); err != nil {
			return err
		}
		var oldConfig oidc.CredentialsConfig
		if err := json.Unmarshal(oldCreds.Config, &oldConfig); err != nil {
			return err
		}
		for _, provider := range newConfig.Providers {
			if err := h.doesAnotherIdentityUseTheseOidcCredentials(ctx, identityId, provider); err != nil {
				return err
			}
		}
		providers := make(map[string]OidcCredentialsWithId)
		// add all old providers
		for _, oldV := range oldConfig.Providers {
			providers[oldV.Provider] = OidcCredentialsWithId{id: credentialsId(oldV), credentials: oldV}
		}
		// add all new providers, overwriting old ones
		for _, newV := range newConfig.Providers {
			providers[newV.Provider] = OidcCredentialsWithId{id: credentialsId(newV), credentials: newV}
		}
		var newProviders []oidc.ProviderCredentialsConfig
		var newIds []string
		for _, v := range providers {
			newProviders = append(newProviders, v.credentials)
			newIds = append(newIds, v.id)
		}
		oldConfig.Providers = newProviders
		oldCreds.Identifiers = newIds
		if err := h.replaceConfig(oldCreds, oldConfig); err != nil {
			return err
		}
		return nil
	} else if newCreds.Type == identity.CredentialsTypePassword {
		// for password just override with the new one - no need to compare with the existing contents
		var newConfig password.CredentialsConfig
		if err := json.Unmarshal(newCreds.Config, &newConfig); err != nil {
			return err
		}
		if err := h.replaceConfig(oldCreds, newConfig); err != nil {
			return err
		}
		return nil
	}
	return errors.WithStack(ErrUnexpectedProviderType)
}

func (h *Handler) replaceConfig(oldCreds *identity.Credentials, oldConfig interface{}) error {
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(oldConfig); err != nil {
		return err
	}
	oldCreds.Config = b.Bytes()
	return nil
}

func (h *Handler) doesAnotherIdentityUseTheseOidcCredentials(ctx context.Context, identityId uuid.UUID, provider oidc.ProviderCredentialsConfig) error {
	i, _, err := h.r.PrivilegedIdentityPool().FindByCredentialsIdentifier(ctx, identity.CredentialsTypeOIDC, credentialsId(provider))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if i != nil && i.ID != identityId {
		return errors.WithStack(herodot.ErrBadRequest.WithReason("These OIDC credentials are already used by another identity"))
	}
	return nil
}

func credentialsId(provider oidc.ProviderCredentialsConfig) string {
	return fmt.Sprintf("%s:%s", provider.Provider, provider.Subject)
}