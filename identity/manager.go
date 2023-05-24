package identity

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/gofrs/uuid"

	"github.com/mohae/deepcopy"
	"github.com/pkg/errors"

	"github.com/ory/herodot"
	"github.com/ory/jsonschema/v3"
	"github.com/ory/x/errorsx"

	"github.com/ory/kratos/courier"
)

var ErrProtectedFieldModified = herodot.ErrForbidden.
	WithReasonf(`A field was modified that updates one or more credentials-related settings. This action was blocked because an unprivileged method was used to execute the update. This is either a configuration issue or a bug and should be reported to the system administrator.`)

type (
	managerDependencies interface {
		PoolProvider
		courier.Provider
		ValidationProvider
		ActiveCredentialsCounterStrategyProvider
		PrivilegedPoolProvider
	}
	ManagementProvider interface {
		IdentityManager() *Manager
	}
	Manager struct {
		r managerDependencies
	}

	managerOptions struct {
		ExposeValidationErrors    bool
		AllowWriteProtectedTraits bool
	}

	ManagerOption func(*managerOptions)
)

func NewManager(r managerDependencies) *Manager {
	return &Manager{r: r}
}

func ManagerExposeValidationErrorsForInternalTypeAssertion(options *managerOptions) {
	options.ExposeValidationErrors = true
}

func ManagerAllowWriteProtectedTraits(options *managerOptions) {
	options.AllowWriteProtectedTraits = true
}

func newManagerOptions(opts []ManagerOption) *managerOptions {
	var o managerOptions
	for _, f := range opts {
		f(&o)
	}
	return &o
}

func (m *Manager) Create(ctx context.Context, i *Identity, opts ...ManagerOption) error {
	o := newManagerOptions(opts)
	if err := m.validate(ctx, i, o); err != nil {
		return err
	}

	return m.r.IdentityPool().(PrivilegedPool).CreateIdentity(ctx, i)
}

func (m *Manager) requiresPrivilegedAccess(_ context.Context, original, updated *Identity, o *managerOptions) error {
	if !o.AllowWriteProtectedTraits {
		if !CredentialsEqual(updated.Credentials, original.Credentials) {
			// reset the identity
			*updated = *original
			return errors.WithStack(ErrProtectedFieldModified)
		}

		if !reflect.DeepEqual(original.VerifiableAddresses, updated.VerifiableAddresses) &&
			/* prevent nil != []string{} */
			len(original.VerifiableAddresses)+len(updated.VerifiableAddresses) != 0 {
			// reset the identity
			*updated = *original
			return errors.WithStack(ErrProtectedFieldModified)
		}
	}
	return nil
}

func (m *Manager) Update(ctx context.Context, updated *Identity, opts ...ManagerOption) error {
	o := newManagerOptions(opts)
	if err := m.validate(ctx, updated, o); err != nil {
		return err
	}

	original, err := m.r.IdentityPool().(PrivilegedPool).GetIdentityConfidential(ctx, updated.ID)
	if err != nil {
		return err
	}

	if err := m.requiresPrivilegedAccess(ctx, original, updated, o); err != nil {
		return err
	}

	return m.r.IdentityPool().(PrivilegedPool).UpdateIdentity(ctx, updated)
}

func (m *Manager) UpdateSchemaID(ctx context.Context, id uuid.UUID, schemaID string, opts ...ManagerOption) error {
	o := newManagerOptions(opts)
	original, err := m.r.IdentityPool().(PrivilegedPool).GetIdentityConfidential(ctx, id)
	if err != nil {
		return err
	}

	if !o.AllowWriteProtectedTraits && original.SchemaID != schemaID {
		return errors.WithStack(ErrProtectedFieldModified)
	}

	original.SchemaID = schemaID
	if err := m.validate(ctx, original, o); err != nil {
		return err
	}

	return m.r.IdentityPool().(PrivilegedPool).UpdateIdentity(ctx, original)
}

func (m *Manager) SetTraits(ctx context.Context, id uuid.UUID, traits Traits, opts ...ManagerOption) (*Identity, error) {
	o := newManagerOptions(opts)
	original, err := m.r.IdentityPool().(PrivilegedPool).GetIdentityConfidential(ctx, id)
	if err != nil {
		return nil, err
	}

	// original is used to check whether protected traits were modified
	updated := deepcopy.Copy(original).(*Identity)
	updated.Traits = traits

	// fandom-start - update email verification status on email change
	// this is hacky way to update metadata_public using json.RawMessage
	origTraits := struct {
		Email string `json:"email,omitempty"`
	}{}
	newTraits := origTraits
	if json.Unmarshal(original.Traits, &origTraits) == nil && json.Unmarshal(traits, &newTraits) == nil && newTraits.Email != origTraits.Email {
		if updated.MetadataPublic == nil {
			updated.MetadataPublic = []byte(`{"email_verified": false}`)
		} else {
			var data map[string]json.RawMessage
			if err = json.Unmarshal(updated.MetadataPublic, &data); err == nil {
				if data == nil {
					data = map[string]json.RawMessage{}
				}
				data["email_verified"] = []byte("false")
			}
			if payload, err := json.Marshal(data); err == nil {
				updated.MetadataPublic = payload
			}
		}
	}
	// fandom-end

	if err := m.validate(ctx, updated, o); err != nil {
		return nil, err
	}

	if err := m.requiresPrivilegedAccess(ctx, original, updated, o); err != nil {
		return nil, err
	}

	return updated, nil
}

func (m *Manager) UpdateTraits(ctx context.Context, id uuid.UUID, traits Traits, opts ...ManagerOption) error {
	updated, err := m.SetTraits(ctx, id, traits, opts...)
	if err != nil {
		return err
	}

	return m.r.IdentityPool().(PrivilegedPool).UpdateIdentity(ctx, updated)
}

func (m *Manager) validate(ctx context.Context, i *Identity, o *managerOptions) error {
	if err := m.r.IdentityValidator().Validate(ctx, i); err != nil {
		if _, ok := errorsx.Cause(err).(*jsonschema.ValidationError); ok && !o.ExposeValidationErrors {
			return herodot.ErrBadRequest.WithReasonf("%s", err).WithWrap(err)
		}
		return err
	}

	return nil
}

func (m *Manager) CountActiveFirstFactorCredentials(ctx context.Context, i *Identity) (count int, err error) {
	for _, strategy := range m.r.ActiveCredentialsCounterStrategies(ctx) {
		current, err := strategy.CountActiveFirstFactorCredentials(i.Credentials)
		if err != nil {
			return 0, err
		}

		count += current
	}
	return count, nil
}

func (m *Manager) CountActiveMultiFactorCredentials(ctx context.Context, i *Identity) (count int, err error) {
	for _, strategy := range m.r.ActiveCredentialsCounterStrategies(ctx) {
		current, err := strategy.CountActiveMultiFactorCredentials(i.Credentials)
		if err != nil {
			return 0, err
		}

		count += current
	}
	return count, nil
}

// Fandom-start https://github.com/Wikia/kratos/pull/84
func (m *Manager) GetIdentityHighestAAL(ctx context.Context, identityId uuid.UUID) (available AuthenticatorAssuranceLevel, err error) {
	available = NoAuthenticatorAssuranceLevel
	identity, err := m.r.PrivilegedIdentityPool().GetIdentityConfidential(ctx, identityId)
	if err != nil {
		return available, err
	}
	if firstCount, err := m.CountActiveFirstFactorCredentials(ctx, identity); err != nil {
		return available, err
	} else if firstCount > 0 {
		available = AuthenticatorAssuranceLevel1
	}

	if secondCount, err := m.CountActiveMultiFactorCredentials(ctx, identity); err != nil {
		return available, err
	} else if secondCount > 0 {
		available = AuthenticatorAssuranceLevel2
	}
	return available, nil
}

// Fandom-end
