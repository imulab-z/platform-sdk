package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/spi"
	"sync"
)

type RefreshHandler struct {
	AccessTokenHelper    *AccessTokenHelper
	RefreshTokenHelper   *RefreshTokenHelper
	AccessTokenRepo      AccessTokenRepository
	RefreshTokenRepo     RefreshTokenRepository
	RefreshTokenStrategy RefreshTokenStrategy
}

func (h *RefreshHandler) UpdateSession(ctx context.Context, req TokenRequest) error {
	if !h.SupportsTokenRequest(req) {
		return nil
	}

	oldReq, err := h.reviveAuthorizeRequest(ctx, req)
	if err != nil {
		return err
	}

	req.GetSession().SetLastRequestId(oldReq.GetId())
	req.GetSession().Merge(oldReq.GetSession())

	return nil
}

// Returns the issuing authorization request and a nil error if the provided refresh token is valid; otherwise returns a
// non-nil error if the refresh token is invalid, malformed or is being used illegally.
func (h *RefreshHandler) reviveAuthorizeRequest(ctx context.Context, req TokenRequest) (Request, error) {
	var (
		oldReq Request
		err    error
	)

	if !ClientRegisteredGrantType(req.GetClient(), spi.GrantTypeRefresh) {
		return nil, spi.ErrInvalidGrant("client not capable of using refresh_token grants.")
	}

	err = h.RefreshTokenStrategy.ValidateToken(ctx, req.GetRefreshToken(), req)
	if err != nil {
		return nil, err
	}

	oldReq, err = h.RefreshTokenRepo.GetRequest(ctx, req.GetRefreshToken())
	if err != nil {
		return nil, err
	}

	return oldReq, nil
}

func (h *RefreshHandler) IssueToken(ctx context.Context, req TokenRequest, resp Response) error {
	if !h.SupportsTokenRequest(req) {
		return nil
	}

	if err := h.deleteOldTokens(ctx, req); err != nil {
		return err
	}

	if err := h.issueNewTokens(ctx, req, resp); err != nil {
		return err
	}

	return nil
}

// Returns nil if successfully removed both access tokens and refresh tokens associated with the authorization request.
// Otherwise, returns a non-nil error. The removal of the two token types are executed asynchronously.
func (h *RefreshHandler) deleteOldTokens(ctx context.Context, req TokenRequest) error {
	errChan := make(chan error, 1)
	defer close(errChan)

	wg := new(sync.WaitGroup)
	wg.Add(2)
	doAsync(ctx, wg, errChan, func() error {
		return h.AccessTokenRepo.DeleteByRequestId(ctx, req.GetSession().GetLastRequestId())
	})
	doAsync(ctx, wg, errChan, func() error {
		return h.RefreshTokenRepo.DeleteByRequestId(ctx, req.GetSession().GetLastRequestId())
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

// Returns nil if successfully issued both new access token and new refresh token. Otherwise returns a non-nil error.
// The issuing process of both token types are executed asynchronously.
func (h *RefreshHandler) issueNewTokens(ctx context.Context, req TokenRequest, resp Response) error {
	errChan := make(chan error, 1)
	defer close(errChan)

	wg := new(sync.WaitGroup)
	wg.Add(2)
	doAsync(ctx, wg, errChan, func() error {
		return h.AccessTokenHelper.GenToken(ctx, req, resp)
	})
	doAsync(ctx, wg, errChan, func() error {
		return h.RefreshTokenHelper.GenToken(ctx, req, resp)
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

func (h *RefreshHandler) SupportsTokenRequest(req TokenRequest) bool {
	return V(req.GetGrantTypes()).ContainsExactly(spi.GrantTypeRefresh)
}
