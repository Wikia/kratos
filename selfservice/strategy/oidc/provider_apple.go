package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/form3tech-oss/jwt-go"
	"github.com/pkg/errors"
	"net/url"
	"time"

	"github.com/ory/x/logrusx"
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

func (a *ProviderApple) newClientSecret() (string, error) {
	logger := logrusx.New("AppleProvider", "")
	logger.Info("Generating new JWT token")

	// decode the pem format
	block, _ := pem.Decode([]byte(a.config.PrivateKey))
	if block == nil || block.Type != "PRIVATE KEY" {
		return "", errors.New("failed to decode PEM block containing private key")
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", errors.New("Private key decoding failed. " + err.Error())
	}
	privateKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", errors.New("Private key is not ecdsa key")
	}

	now := time.Now()
	expirationTime := time.Now().Add(5 * time.Minute)

	appleToken := jwt.NewWithClaims(jwt.SigningMethodES256,
		jwt.StandardClaims{
			Audience:  []string{a.config.IssuerURL},
			ExpiresAt: expirationTime.Unix(),
			IssuedAt:  now.Unix(),
			Issuer:    a.config.TeamId,
			Subject:   a.config.ClientID,
		})
	appleToken.Header["kid"] = a.config.PrivateKeyId

	return appleToken.SignedString(privateKey)
}

func (a *ProviderApple) oauth2() (*oauth2.Config, error) {
	// Apple requires a JWT token that acts as a client secret
	secret, err := a.newClientSecret()
	if err != nil {
		return nil, err
	}
	a.config.ClientSecret = secret

	endpoint := oauth2.Endpoint{
		AuthURL:  a.config.IssuerURL + "/auth/authorize",
		TokenURL: a.config.IssuerURL + "/auth/token",
	}
	return a.oauth2ConfigFromEndpoint(endpoint), nil
}

func (a *ProviderApple) OAuth2(context.Context) (*oauth2.Config, error) {
	return a.oauth2()
}

func (a *ProviderApple) AuthCodeURLOptions(r ider) []oauth2.AuthCodeOption {
	var options []oauth2.AuthCodeOption

	if isForced(r) {
		options = append(options, oauth2.SetAuthURLParam("prompt", "login"))
	}
	if len(a.config.RequestedClaims) != 0 {
		options = append(options, oauth2.SetAuthURLParam("claims", string(a.config.RequestedClaims)))
	}

	// todo - add this only when email or name is requested
	options = append(options, oauth2.SetAuthURLParam("response_mode", "form_post"))

	return options
}