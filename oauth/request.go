package oauth

import (
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/satori/go.uuid"
	"time"
)

// Common OAuth 2.0 Request elements.
type Request interface {
	// Returns the id of the request
	GetId()	string
	// Set the id
	SetId(id string)
	// Returns the request timestamp
	GetTimestamp() time.Time
	// Set timestamp
	SetTimestamp(timestamp int64)
	// Returns the client for this request
	GetClient() spi.OAuthClient
	// Set client
	SetClient(client spi.OAuthClient)
	// Returns the requested redirect uri
	GetRedirectUri() string
	// Set redirect uri
	SetRedirectUri(uri string)
	// Get the requested scopes
	GetScopes() []string
	// Set the requested scopes
	AddScopes(scopes ...string)
	// Returns the session
	GetSession() Session
	// Set session
	SetSession(session Session)
}

// Constructs a new default request object with id and timestamp set.
func NewRequest() Request {
	return &oauthRequest{
		Id: uuid.NewV4().String(),
		Timestamp: time.Now().Unix(),
		RedirectUri: "",
		Client: nil,
		Scopes: make([]string, 0),
		Session: NewSession(),
	}
}

type oauthRequest struct {
	Id 			string				`json:"id"`
	Timestamp	int64				`json:"timestamp"`
	Client 		spi.OAuthClient		`json:"client"`
	RedirectUri	string				`json:"redirect_uri"`
	Scopes		[]string			`json:"scopes"`
	Session 	Session				`json:"session"`
}

func (r *oauthRequest) GetId() string {
	return r.Id
}

func (r *oauthRequest) SetId(id string) {
	r.Id = id
}

func (r *oauthRequest) GetScopes() []string {
	return r.Scopes
}

func (r *oauthRequest) AddScopes(scopes ...string) {
	r.Scopes = append(r.Scopes, scopes...)
}

func (r *oauthRequest) GetTimestamp() time.Time {
	return time.Unix(r.Timestamp, 0)
}

func (r *oauthRequest) SetTimestamp(timestamp int64) {
	r.Timestamp = timestamp
}

func (r *oauthRequest) GetClient() spi.OAuthClient {
	return r.Client
}

func (r *oauthRequest) SetClient(client spi.OAuthClient) {
	r.Client = client
}

func (r *oauthRequest) GetRedirectUri() string {
	return r.RedirectUri
}

func (r *oauthRequest) SetRedirectUri(uri string) {
	r.RedirectUri = uri
}

func (r *oauthRequest) GetSession() Session {
	return r.Session
}

func (r *oauthRequest) SetSession(session Session) {
	r.Session = session
}
