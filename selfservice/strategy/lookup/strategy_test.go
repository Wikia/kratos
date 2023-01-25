package lookup_test

import (
	"fmt"
	"testing"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/selfservice/strategy/lookup"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
)

func TestCountActiveFirstFactorCredentials(t *testing.T) {
	conf, reg := internal.NewFastRegistryWithMocks(t)
	strategy := lookup.NewStrategy(reg)

	t.Run("first factor", func(t *testing.T) {
		actual, err := strategy.CountActiveFirstFactorCredentials(nil)
		require.NoError(t, err)
		assert.Equal(t, 0, actual)
	})

	t.Run("multi factor", func(t *testing.T) {
		for k, tc := range []struct {
			in       identity.CredentialsCollection
			config   []byte
			expected int
		}{
			{
				in: identity.CredentialsCollection{{
					Type:   strategy.ID(),
					Config: []byte{},
				}},
				config:   []byte(`{}`),
				expected: 0,
			},
			{
				in: identity.CredentialsCollection{{
					Type:   strategy.ID(),
					Config: []byte(`{"recovery_codes": []}`),
				}},
				config:   []byte(`{}`),
				expected: 0,
			},
			{
				in: identity.CredentialsCollection{{
					Type:        strategy.ID(),
					Identifiers: []string{"foo"},
					Config:      []byte(`{"recovery_codes": [{}]}`),
				}},
				config:   []byte(`{}`),
				expected: 1,
			},
			{
				in: identity.CredentialsCollection{{
					Type:   strategy.ID(),
					Config: []byte(`{}`),
				}},
				config:   []byte(`{}`),
				expected: 0,
			},
			{
				in:       identity.CredentialsCollection{{}, {}},
				config:   []byte(`{}`),
				expected: 0,
			},
			// fandom-start
			{
				in: identity.CredentialsCollection{{
					Type:        strategy.ID(),
					Identifiers: []string{"foo"},
					Config:      []byte(`{"recovery_codes": [{}]}`),
				}},
				config:   []byte(`{"enabled_only_in_2fa": true}`),
				expected: 0,
			},
			// fandom-end
		} {
			t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
				cc := map[identity.CredentialsType]identity.Credentials{}
				for _, c := range tc.in {
					cc[c.Type] = c
				}

				conf.MustSet(fmt.Sprintf("%s.%s.config", config.ViperKeySelfServiceStrategyConfig, strategy.ID()), tc.config)
				actual, err := strategy.CountActiveMultiFactorCredentials(cc)
				require.NoError(t, err)
				assert.Equal(t, tc.expected, actual)
			})
		}
	})
}
