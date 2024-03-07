package authenticator

import (
	"context"
	"errors"
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

	conf := oauth2.Config{
		ClientID:     os.Getenv("OAUTH_CLIENT"),
		ClientSecret: os.Getenv("OAUTH_SECRET"),
		RedirectURL:  os.Getenv("OAUTH_CALLBACK"),
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
	}

	return &Authenticator{
		Provider: provider,
		Config:   conf,
	}, nil
}

func (authenticator *Authenticator) VerifyIDToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("no id_token field in oauth token")
	}

	oidcConfig := &oidc.Config{
		ClientID: authenticator.ClientID,
	}

	return authenticator.Verifier(oidcConfig).Verify(ctx, rawIDToken)
}
