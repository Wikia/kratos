// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"context"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow/registration"
)

func filter(hooks []config.SelfServiceHook, persistencePhase config.PersistencePhase) (ret []config.SelfServiceHook) {
	for _, h := range hooks {
		if len(h.PersistencePhase) == 0 || h.PersistencePhase == config.All || h.PersistencePhase == persistencePhase {
			ret = append(ret, h)
		}
	}
	return
}

func (m *RegistryDefault) PostRegistrationPrePersistHooks(ctx context.Context, credentialsType identity.CredentialsType) (b []registration.PostHookPrePersistExecutor) {
	if credentialsType == identity.CredentialsTypeCodeAuth && m.Config().SelfServiceCodeStrategy(ctx).PasswordlessEnabled {
		b = append(b, m.HookCodeAddressVerifier())
	}

	for _, v := range m.getHooks(string(credentialsType), filter(m.Config().SelfServiceFlowRegistrationAfterHooks(ctx, string(credentialsType)), config.PrePersist)) {
		if hook, ok := v.(registration.PostHookPrePersistExecutor); ok {
			b = append(b, hook)
		}
	}

	return
}

func (m *RegistryDefault) PostRegistrationPostPersistHooks(ctx context.Context, credentialsType identity.CredentialsType) (b []registration.PostHookPostPersistExecutor) {
	initialHookCount := 0
	if m.Config().SelfServiceFlowVerificationEnabled(ctx) {
		b = append(b, m.HookVerifier())
		initialHookCount = 1
	}

	for _, v := range m.getHooks(string(credentialsType), filter(m.Config().SelfServiceFlowRegistrationAfterHooks(ctx, string(credentialsType)), config.PostPersist)) {
		if hook, ok := v.(registration.PostHookPostPersistExecutor); ok {
			b = append(b, hook)
		}
	}

	if len(b) == initialHookCount {
		// since we don't want merging hooks defined in a specific strategy and
		// global hooks are added only if no strategy specific hooks are defined
		for _, v := range m.getHooks(config.HookGlobal, filter(m.Config().SelfServiceFlowRegistrationAfterHooks(ctx, config.HookGlobal), config.PostPersist)) {
			if hook, ok := v.(registration.PostHookPostPersistExecutor); ok {
				b = append(b, hook)
			}
		}
	}

	return
}

func (m *RegistryDefault) PreRegistrationHooks(ctx context.Context) (b []registration.PreHookExecutor) {
	for _, v := range m.getHooks("", m.Config().SelfServiceFlowRegistrationBeforeHooks(ctx)) {
		if hook, ok := v.(registration.PreHookExecutor); ok {
			b = append(b, hook)
		}
	}
	return
}

func (m *RegistryDefault) RegistrationExecutor() *registration.HookExecutor {
	if m.selfserviceRegistrationExecutor == nil {
		m.selfserviceRegistrationExecutor = registration.NewHookExecutor(m)
	}
	return m.selfserviceRegistrationExecutor
}

func (m *RegistryDefault) RegistrationHookExecutor() *registration.HookExecutor {
	if m.selfserviceRegistrationExecutor == nil {
		m.selfserviceRegistrationExecutor = registration.NewHookExecutor(m)
	}
	return m.selfserviceRegistrationExecutor
}

func (m *RegistryDefault) RegistrationErrorHandler() *registration.ErrorHandler {
	if m.seflserviceRegistrationErrorHandler == nil {
		m.seflserviceRegistrationErrorHandler = registration.NewErrorHandler(m)
	}
	return m.seflserviceRegistrationErrorHandler
}

func (m *RegistryDefault) RegistrationHandler() *registration.Handler {
	if m.selfserviceRegistrationHandler == nil {
		m.selfserviceRegistrationHandler = registration.NewHandler(m)
	}

	return m.selfserviceRegistrationHandler
}

func (m *RegistryDefault) RegistrationFlowErrorHandler() *registration.ErrorHandler {
	if m.selfserviceRegistrationRequestErrorHandler == nil {
		m.selfserviceRegistrationRequestErrorHandler = registration.NewErrorHandler(m)
	}

	return m.selfserviceRegistrationRequestErrorHandler
}
