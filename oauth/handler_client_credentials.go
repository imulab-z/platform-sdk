package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/spi"
	"sync"
)

type ClientCredentialsHandler struct {
	AccessTokenHelper 	*AccessTokenHelper
	RefreshTokenHelper 	*RefreshTokenHelper
	ScopeComparator		Comparator
}

func (h *ClientCredentialsHandler) UpdateSession(ctx context.Context, req TokenRequest) error {
	if !h.SupportsTokenRequest(req) {
		return nil
	}

	if err := h.checkClientCapability(req); err != nil {
		return err
	}

	// automatically grant all registered scopes
	req.GetSession().AddGrantedScopes(req.GetScopes()...)

	return nil
}

// Checks the client capability to request token through client_credentials flow. Returns nil if the capability checks
// out; otherwise returns a non-nil error if the client is not public, didn't registered client_credentials grant type
// or doesn't accept the requested scopes.
func (h *ClientCredentialsHandler) checkClientCapability(req TokenRequest) error {
	if req.GetClient().GetType() == spi.ClientTypePublic {
		return spi.ErrInvalidClient("public client cannot use client_credentials flow.", "")
	}

	if !ClientRegisteredGrantType(req.GetClient(), spi.GrantTypeClient) {
		return spi.ErrInvalidGrant("client unable to use client_credentials grant.")
	}

	if !ClientAcceptsScopes(req, h.ScopeComparator) {
		return spi.ErrInvalidScope("scope is not accepted by client.")
	}

	return nil
}

func (h *ClientCredentialsHandler) IssueToken(ctx context.Context, req TokenRequest, resp Response) error {
	if !h.SupportsTokenRequest(req) {
		return nil
	}

	errChan := make(chan error, 1)
	defer close(errChan)

	wg := new(sync.WaitGroup)
	wg.Add(2)
	doAsync(ctx, wg, errChan, func() error {
		return h.AccessTokenHelper.GenToken(ctx, req, resp)
	})
	doAsync(ctx, wg, errChan, func() error {
		if V(req.GetSession().GetGrantedScopes()).Contains(spi.ScopeOfflineAccess) {
			return h.RefreshTokenHelper.GenToken(ctx, req, resp)
		} else {
			return nil
		}
	})
	wg.Wait()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errChan:
		return err
	default:
		return nil
	}
}

func (h *ClientCredentialsHandler) SupportsTokenRequest(req TokenRequest) bool {
	return V(req.GetGrantTypes()).ContainsExactly(spi.GrantTypeClient)
}
