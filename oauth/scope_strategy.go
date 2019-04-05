package oauth

import (
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/thoas/go-funk"
)

var (
	ErrClientRejectScope = spi.ErrInvalidScope("one or more scope is not granted by the client.")
)

type ScopeStrategy interface {
	// Returns true if client accepts the scope; false otherwise
	Accepts(client spi.OAuthClient, scope string) bool
	// Returns true if client accepts all scopes; false otherwise
	AcceptsAll(client spi.OAuthClient, scopes []string) bool
}

func NewEqualScopeStrategy() ScopeStrategy {
	return &equalScopeStrategy{}
}

type equalScopeStrategy struct {}

func (_ *equalScopeStrategy) Accepts(client spi.OAuthClient, scope string) bool {
	return funk.ContainsString(client.GetScopes(), scope)
}

func (_ *equalScopeStrategy) AcceptsAll(client spi.OAuthClient, scopes []string) bool {
	for _, s := range scopes {
		if !funk.ContainsString(client.GetScopes(), s) {
			return false
		}
	}
	return true
}

