package oauth

import "context"

// AccessTokenRepository no-operation implementation
type noOpAccessTokenRepo struct {}

func (r *noOpAccessTokenRepo) Save(ctx context.Context, token string, req Request) error {
	return nil
}

func (r *noOpAccessTokenRepo) GetRequest(ctx context.Context, token string) (Request, error) {
	return nil, nil
}

func (r *noOpAccessTokenRepo) Delete(ctx context.Context, token string) error {
	return nil
}

func (r *noOpAccessTokenRepo) DeleteByRequestId(ctx context.Context, requestId string) error {
	return nil
}

// OAuthClient panic implementation
type panicClient struct {}

func (c *panicClient) GetId() string {
	panic("implement GetId")
}

func (c *panicClient) GetName() string {
	panic("implement GetName")
}

func (c *panicClient) GetType() string {
	panic("implement GetType")
}

func (c *panicClient) GetRedirectUris() []string {
	panic("implement GetRedirectUris")
}

func (c *panicClient) GetResponseTypes() []string {
	panic("implement GetResponseTypes")
}

func (c *panicClient) GetGrantTypes() []string {
	panic("implement GetGrantTypes")
}

func (c *panicClient) GetScopes() []string {
	panic("implement GetScopes")
}
