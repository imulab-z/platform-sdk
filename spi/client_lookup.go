package spi

import "context"

type ClientLookup interface {
	// Find a Open ID Connect 1.0 client by its id. Returns either the client or
	// a descriptive error. Implementations are encouraged to return OAuthError typed error.
	FindById(ctx context.Context, id string) (OidcClient, error)
}
