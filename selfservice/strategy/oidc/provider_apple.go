package oidc

import (
	"net/url"

	"golang.org/x/oauth2"
)

type ProviderApple struct {
	*ProviderGenericOIDC
}

func NewProviderApple(
	config *Configuration,
	public *url.URL,
) *ProviderApple {
	config.IssuerURL = "https://appleid.apple.com"

	return &ProviderApple{
		ProviderGenericOIDC: &ProviderGenericOIDC{
			config: config,
			public: public,
		},
	}
}

func (g *ProviderApple) AuthCodeURLOptions(r ider) []oauth2.AuthCodeOption {
	var options []oauth2.AuthCodeOption

	if isForced(r) {
		options = append(options, oauth2.SetAuthURLParam("prompt", "login"))
	}
	if len(g.config.RequestedClaims) != 0 {
		options = append(options, oauth2.SetAuthURLParam("claims", string(g.config.RequestedClaims)))
	}

	// todo - add this only when email or name is requested
	//options = append(options, oauth2.SetAuthURLParam("response_mode", "form_post"))

	return options
}
