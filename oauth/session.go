package oauth

// Interface for a user session during the request
type Session interface {
	// Returns the user subject that authorized this request.
	GetSubject() string
	// Sets a new user subject
	setSubject(subject string)
	// Returns user's granted scopes.
	GetGrantedScopes() []string
	// Adds new scopes to the granted list
	addGrantedScopes(scopes ...string)
	// Returns claims to be added in the issued access token.
	GetAccessClaims() map[string]interface{}
	// Clone the user session
	Clone() Session
}

// Constructs an empty new session.
func NewSession() Session {
	return &oauthSession{
		Subject: "",
		Scopes: make([]string, 0),
		Claims: make(map[string]interface{}),
	}
}

// internal implementation of Session interface.
type oauthSession struct {
	Subject 	string					`json:"subject"`
	Scopes		[]string				`json:"granted_scopes"`
	Claims 		map[string]interface{}	`json:"claims"`
}

func (s *oauthSession) setSubject(subject string) {
	s.Subject = subject
}

func (s *oauthSession) addGrantedScopes(scopes ...string) {
	s.Scopes = append(s.Scopes, scopes...)
}

func (s *oauthSession) GetSubject() string {
	return s.Subject
}

func (s *oauthSession) GetGrantedScopes() []string {
	return s.Scopes
}

func (s *oauthSession) GetAccessClaims() map[string]interface{} {
	return s.Claims
}

func (s *oauthSession) Clone() Session {
	grantedScopesCopy := make([]string, len(s.Scopes))
	copy(grantedScopesCopy, s.Scopes)

	accessClaimsCopy := make(map[string]interface{})
	for k, v := range s.Claims {
		accessClaimsCopy[k] = v
	}

	return &oauthSession{
		Subject: s.Subject,
		Scopes: grantedScopesCopy,
		Claims: accessClaimsCopy,
	}
}
