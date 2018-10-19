package auth

import (
	"golang.org/x/oauth2"
)

// OAuth2Provider provides authentication service with OAUTH2 service
type OAuth2Provider struct {
	oauth2.TokenSource
}

var _ Provider = (*OAuth2Provider)(nil)
