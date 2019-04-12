package spi

import "fmt"

// Error model to provide both error and error_description information while also being
// friendly to HTTP response rendering.
type OAuthError struct {
	Err 	string 				`json:"error"`
	Reason	string 				`json:"error_description"`
	Code	int					`json:"-"`
	Headers	map[string]string	`json:"-"`
}

func (e *OAuthError) Error() string {
	return e.Err
}

// Factory method to create an invalid_request error.
// This error should be raised when the request is missing
// a required parameter, includes an unsupported parameter
// value (other than grant type), repeats a parameter, includes
// multiple credentials, utilizes more than one mechanism for
// authenticating the client, or is otherwise malformed.
func ErrInvalidRequest(reason string) *OAuthError {
	return &OAuthError{
		Err: "invalid_request",
		Reason: reason,
		Code: 400,
	}
}

// Factory method to create an invalid_client error. If the authScheme
// parameter is provided, this method will also set the WWW-Authenticate
// header with data in the format of $authScheme error="$error" error_description="$reason".
// This error should be raised when the client authentication
// failed (e.g., unknown client, no client authentication included,
// or unsupported authentication method). The authorization server MAY
// return an HTTP 401 (Unauthorized) status code to indicate
// which HTTP authentication schemes are supported.  If the
// client attempted to authenticate via the "Authorization"
// request header field, the authorization server MUST
// respond with an HTTP 401 (Unauthorized) status code and
// include the "WWW-Authenticate" response header field
// matching the authentication scheme used by the client.
func ErrInvalidClient(reason string, authScheme string) *OAuthError {
	e := &OAuthError{
		Err: "invalid_client",
		Reason: reason,
		Code: 401,
	}

	if len(authScheme) > 0 {
		e.Headers = map[string]string {
			"WWW-Authenticate": fmt.Sprintf("%s error=\"%s\" error_description=\"%s\"",
				authScheme, e.Err, e.Reason),
		}
	}

	return e
}

// Factory method to create an invalid_grant error.
// This error should be raised when the provided authorization
// grant (e.g., authorization code, resource owner credentials)
// or refresh token is invalid, expired, revoked, does not match
// the redirection URI used in the authorization request, or was issued to
// another client.
func ErrInvalidGrant(reason string) *OAuthError {
	return &OAuthError{
		Err: "invalid_grant",
		Reason: reason,
		Code: 400,
	}
}

// Factory method to create an unauthorized_client error.
// This error should be raised when the authenticated client
// is not authorized to use this authorization grant type.
func ErrUnauthorizedClient(reason string) *OAuthError {
	return &OAuthError{
		Err: "unauthorized_client",
		Reason: reason,
		Code: 400,
	}
}

// Factory method to create an unsupported_grant_type error.
// This error should be raised when the authorization grant type
// is not supported by the authorization server.
func ErrUnsupportedGrantType(reason string) *OAuthError {
	return &OAuthError{
		Err: "unsupported_grant_type",
		Reason: reason,
		Code: 400,
	}
}

// Factory method to create an unsupported_response_type error.
// This error should be raised when the authorization server does not
// support obtaining an authorization code using this method.
func ErrUnsupportedResponseType(reason string) *OAuthError {
	return &OAuthError{
		Err: "unsupported_response_type",
		Reason: reason,
		Code: 400,
	}
}

// Factory method to create an invalid_scope error.
// This error should be raised when the requested scope is
// invalid, unknown, malformed, or exceeds the scope granted
// by the resource owner.
func ErrInvalidScope(reason string) *OAuthError {
	return &OAuthError{
		Err: "invalid_scope",
		Reason: reason,
		Code: 400,
	}
}

// Factory method to create an access_denied error.
// This error should be raised when the resource owner or
// authorization server denied the request.
func ErrAccessDenied(reason string) *OAuthError {
	return &OAuthError{
		Err: "access_denied",
		Reason: reason,
		Code: 403,
	}
}

// Factory method to create a server_error error.
// This error should be raised when the authorization server
// encountered an unexpected condition that prevented it from
// fulfilling the request.
func ErrServerError(err error) *OAuthError {
	return &OAuthError{
		Err: "server_error",
		Reason: err.Error(),
		Code: 500,
	}
}

// Convenience function to create server_error with plain message and args.
func ErrServerErrorf(msg string, args ...interface{}) *OAuthError {
	return ErrServerError(fmt.Errorf(msg, args...))
}

// Factory method to create a temporarily_unavailable error.
// The authorization server is currently unable to handle
// the request due to a temporary overloading or maintenance
// of the server.  (This error code is needed because a 503
// Service Unavailable HTTP status code cannot be returned
// to the client via an HTTP redirect.)
func ErrTemporarilyUnavailable() *OAuthError {
	return &OAuthError{
		Err: "temporarily_unavailable",
		Reason: "one or more service is currently unavailable.",
		Code: 503,
	}
}
