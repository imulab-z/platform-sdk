package oauth

import "context"

type AuthorizeHandler interface {
	// Process the authorization request.
	Authorize(ctx context.Context, req AuthorizeRequest, resp Response) error
	// Internal convenience method to determine whether this handler should be skipped.
	SupportsAuthorizeRequest(req AuthorizeRequest) bool
}

type TokenHandler interface {
	// Update session knowledge before processing request.
	UpdateSession(ctx context.Context, req TokenRequest) error
	// Issue token for the request.
	IssueToken(ctx context.Context, req TokenRequest, resp Response) error
	// Internal convenience method to determine whether this handler should be skipped.
	SupportsTokenRequest(req TokenRequest) bool
}