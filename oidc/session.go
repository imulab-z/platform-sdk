package oidc

import (
	"github.com/imulab-z/platform-sdk/oauth"
	"time"
)

type Session interface {
	oauth.Session
	GetObfuscatedSubject() string
	SetObfuscatedSubject(subject string)
	GetAuthTime() time.Time
	SetAuthTime(time time.Time)
	GetAcrValues() []string
	AddAcrValues(values ...string)
	GetNonce() string
	SetNonce(nonce string)
	GetIdTokenClaims() map[string]interface{}
}

func NewSession() Session {
	return &oidcSession{
		Subject: "",
		Scopes: make([]string, 0),
		AccessClaims: make(map[string]interface{}),
		ObfSubject: "",
		AuthTime: 0,
		Nonce: "",
		LastReqId: "",
		AcrValues: make([]string, 0),
		IdTokenClaims: make(map[string]interface{}),
	}
}

type oidcSession struct {
	Subject 		string					`json:"subject"`
	Scopes			[]string				`json:"granted_scopes"`
	AccessClaims 	map[string]interface{}	`json:"access_token_claims"`
	ObfSubject		string					`json:"obfuscated_subject"`
	AuthTime		int64					`json:"auth_time"`
	Nonce			string					`json:"nonce"`
	AcrValues		[]string				`json:"acr_values"`
	IdTokenClaims	map[string]interface{}	`json:"id_token_claims"`
	LastReqId		string					`json:"-"`
}

func (s *oidcSession) GetLastRequestId() string {
	return s.LastReqId
}

func (s *oidcSession) SetLastRequestId(id string) {
	s.LastReqId = id
}

func (s *oidcSession) Clone() oauth.Session {
	grantedScopesCopy := make([]string, len(s.Scopes))
	copy(grantedScopesCopy, s.Scopes)

	accessClaimsCopy := make(map[string]interface{})
	for k, v := range s.AccessClaims {
		accessClaimsCopy[k] = v
	}

	acrValuesCopy := make([]string, len(s.AcrValues))
	copy(acrValuesCopy, s.AcrValues)

	idTokenClaimsCopy := make(map[string]interface{})
	for k, v := range s.IdTokenClaims {
		idTokenClaimsCopy[k] = v
	}

	return &oidcSession{
		Subject: s.Subject,
		Scopes: grantedScopesCopy,
		AccessClaims: accessClaimsCopy,
		ObfSubject: s.ObfSubject,
		AuthTime: s.AuthTime,
		Nonce: s.Nonce,
		AcrValues: acrValuesCopy,
		IdTokenClaims: idTokenClaimsCopy,
	}
}

func (s *oidcSession) GetAccessClaims() map[string]interface{} {
	return s.AccessClaims
}

func (s *oidcSession) GetGrantedScopes() []string {
	return s.Scopes
}

func (s *oidcSession) GetSubject() string {
	return s.Subject
}

func (s *oidcSession) AddGrantedScopes(scopes ...string) {
	s.Scopes = append(s.Scopes, scopes...)
}

func (s *oidcSession) SetSubject(subject string) {
	s.Subject = subject
}

func (s *oidcSession) GetObfuscatedSubject() string {
	return s.ObfSubject
}

func (s *oidcSession) SetObfuscatedSubject(subject string) {
	s.ObfSubject = subject
}

func (s *oidcSession) GetAuthTime() time.Time {
	return time.Unix(s.AuthTime, 0)
}

func (s *oidcSession) SetAuthTime(time time.Time) {
	s.AuthTime = time.Unix()
}

func (s *oidcSession) GetAcrValues() []string {
	return s.AcrValues
}

func (s *oidcSession) AddAcrValues(values ...string) {
	s.AcrValues = append(s.AcrValues, values...)
}

func (s *oidcSession) GetNonce() string {
	return s.Nonce
}

func (s *oidcSession) SetNonce(nonce string) {
	s.Nonce = nonce
}

func (s *oidcSession) GetIdTokenClaims() map[string]interface{} {
	return s.IdTokenClaims
}

func (s *oidcSession) Merge(another oauth.Session) {
	if len(s.Subject) == 0 {
		s.Subject = another.GetSubject()
	}

	s.AddGrantedScopes(another.GetGrantedScopes()...)

	for k, v := range another.GetAccessClaims() {
		s.AccessClaims[k] = v
	}

	if another, ok := another.(Session); ok {
		if len(s.ObfSubject) == 0 {
			s.ObfSubject = another.GetObfuscatedSubject()
		}

		if s.AuthTime == 0 {
			s.AuthTime = another.GetAuthTime().Unix()
		}

		s.AddAcrValues(another.GetAcrValues()...)

		if len(s.Nonce) == 0 {
			s.Nonce = another.GetNonce()
		}

		for k, v := range another.GetIdTokenClaims() {
			s.GetIdTokenClaims()[k] = v
		}
	}
}

