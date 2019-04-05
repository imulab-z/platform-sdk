package oauth

import "context"

type AuthorizeHandler interface {
	// Process the authorization request.
	Handle(ctx context.Context, req AuthorizeRequest, resp AuthorizeResponse) error
	// Internal convenience method to determine whether this handler should be skipped.
	supported(req AuthorizeRequest) bool
}

type TokenHandler interface {
	// Update session knowledge before processing request.
	UpdateSession(ctx context.Context, req TokenRequest) error
	// Issue token for the request.
	Handle(ctx context.Context, req TokenRequest, resp TokenResponse) error
}