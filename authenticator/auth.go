package authenticator

import (
	"context"
	"fmt"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Authenticator struct {
	*oidc.Provider
	oauth2.Config
}

func NewAuthenticator() (*Authenticator, error) {
	provider, err := oidc.NewProvider(
		context.Background(),
		"https://"+os.Getenv("OAUTH_DOMAIN")+"/",
	)
	if err != nil {
		return nil, err
	}

	endpoint := provider.Endpoint()
	fmt.Println(endpoint.AuthURL)
	conf := oauth2.Config{
		ClientID:     os.Getenv("OAUTH_CLIENT"),
		ClientSecret: os.Getenv("OAUTH_SECRET"),
		RedirectURL:  os.Getenv("OAUTH_CALLBACK"),
		Endpoint:     endpoint,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "offline_access", "email"},
	}

	return &Authenticator{
		Provider: provider,
		Config:   conf,
	}, nil
}

func (authenticator *Authenticator) VerifyIDToken(ctx context.Context, idToken string) (*oidc.IDToken, error) {
	oidcConfig := &oidc.Config{
		ClientID: authenticator.ClientID,
	}

	return authenticator.Verifier(oidcConfig).Verify(ctx, idToken)
}
