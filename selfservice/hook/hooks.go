package hook

const (
	KeySessionIssuer              = "session"
	KeySessionDestroyer           = "revoke_active_sessions"
	KeyWebHook                    = "web_hook"
	KeyAddressVerifier            = "require_verified_address"
	KeyTotpLookupSecretsDestroyer = "totp_destroys_lookup_secrets"
)
