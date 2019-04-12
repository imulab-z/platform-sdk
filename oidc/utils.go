package oidc

import "github.com/imulab-z/platform-sdk/oauth"

// Returns true if the given oauth.Session is in fact an oidc.Session
func IsOidcSession(session oauth.Session) bool {
	_, ok := session.(Session)
	return ok
}