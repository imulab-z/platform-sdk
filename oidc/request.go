package oidc

import (
	"github.com/imulab-z/platform-sdk/oauth"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/satori/go.uuid"
	"time"
)

func NewRequest() oauth.Request {
	return &oidcRequest{
		Id: uuid.NewV4().String(),
		Timestamp: time.Now().Unix(),
		RedirectUri: "",
		Client: nil,
		OidcSession: NewSession(),
	}
}

type oidcRequest struct {
	Id          string         `json:"id"`
	Timestamp   int64          `json:"timestamp"`
	Client      spi.OidcClient `json:"client"`
	RedirectUri string         `json:"redirect_uri"`
	OidcSession Session        `json:"session"`
}

func (r *oidcRequest) GetId() string {
	return r.Id
}

func (r *oidcRequest) SetId(id string) {
	r.Id = id
}

func (r *oidcRequest) GetTimestamp() time.Time {
	return time.Unix(r.Timestamp, 0)
}

func (r *oidcRequest) SetTimestamp(timestamp int64) {
	r.Timestamp = timestamp
}

func (r *oidcRequest) GetClient() spi.OAuthClient {
	return r.Client
}

func (r *oidcRequest) SetClient(client spi.OAuthClient) {
	if _, ok := client.(spi.OidcClient); !ok {
		panic("only accepts OidcClient")
	}
	r.Client = client.(spi.OidcClient)
}

func (r *oidcRequest) GetRedirectUri() string {
	return r.RedirectUri
}

func (r *oidcRequest) SetRedirectUri(uri string) {
	r.RedirectUri = uri
}

func (r *oidcRequest) GetSession() oauth.Session {
	return r.OidcSession
}

func (r *oidcRequest) SetSession(session oauth.Session) {
	if _, ok := session.(Session); !ok {
		panic("only accepts oidc.OidcSession")
	}
	r.OidcSession = session.(Session)
}
