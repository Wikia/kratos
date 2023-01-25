package hook

const (
	KeySessionIssuer    = "session"
	KeySessionDestroyer = "revoke_active_sessions"
	KeyWebHook          = "web_hook"
	KeyAddressVerifier  = "require_verified_address"
	// fandom-start

	KeyTotpLookupSecretsDestroyer = "totp_destroys_lookup_secrets" // nolint:gosec
	// fandom-end
)
