// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package hook

import (
	"net/http"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow/settings"
)

var _ settings.PostHookPrePersistExecutor = new(TotpSecretsDestroyer)

type (
	totpSecretsDestroyerDependencies interface {
		identity.PrivilegedPoolProvider
	}
	TotpSecretsDestroyer struct {
		r totpSecretsDestroyerDependencies
	}
)

func NewTotpSecretsDestroyer(r totpSecretsDestroyerDependencies) *TotpSecretsDestroyer {
	return &TotpSecretsDestroyer{r: r}
}

func (t *TotpSecretsDestroyer) ExecuteSettingsPrePersistHook(w http.ResponseWriter, r *http.Request, _ *settings.Flow, i *identity.Identity, settingsType string) error {
	// sanity check
	if settingsType != "totp" {
		return nil
	}

	_, hasTotp := i.GetCredentials(identity.CredentialsTypeTOTP)
	_, hasLookupSecrets := i.GetCredentials(identity.CredentialsTypeLookup)
	if !hasTotp && hasLookupSecrets {
		i.DeleteCredentialsType(identity.CredentialsTypeLookup)
	}

	return nil
}
