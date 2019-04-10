package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/thoas/go-funk"
	"sync"
)

type RefreshHandler struct {
	AccessTokenHelper 		*AccessTokenHelper
	RefreshTokenHelper 		*RefreshTokenHelper
	AccessTokenRepo			AccessTokenRepository
	RefreshTokenRepo 		RefreshTokenRepository
	RefreshTokenStrategy	RefreshTokenStrategy
}

func (h *RefreshHandler) UpdateSession(ctx context.Context, req TokenRequest) error {
	if !h.supportsTokenRequest(req) {
		return nil
	}

	if !funk.ContainsString(req.GetClient().GetGrantTypes(), spi.GrantTypeRefresh) {
		return spi.ErrInvalidGrant("client not capable of using refresh_token grants.")
	}

	if err := h.RefreshTokenStrategy.ValidateToken(ctx, req.GetRefreshToken(), req); err != nil {
		return err
	} else if oldReq, err := h.RefreshTokenRepo.GetRequest(ctx, req.GetRefreshToken()); err != nil {
		return err
	} else {
		req.GetSession().SetLastRequestId(oldReq.GetId())
		req.GetSession().Merge(oldReq.GetSession())
	}

	return nil
}

func (h *RefreshHandler) IssueToken(ctx context.Context, req TokenRequest, resp Response) error {
	if !h.supportsTokenRequest(req) {
		return nil
	}

	errChan := make(chan error, 1)
	defer close(errChan)

	wg := new(sync.WaitGroup)
	wg.Add(2)

	go func() {
		defer wg.Done()
		if err := h.AccessTokenRepo.DeleteByRequestId(ctx, req.GetSession().GetLastRequestId()); err != nil {
			select {
			case <-ctx.Done():
				return
			case errChan <- err:
				return
			default:
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		if err := h.RefreshTokenRepo.DeleteByRequestId(ctx, req.GetSession().GetLastRequestId()); err != nil {
			select {
			case <-ctx.Done():
				return
			case errChan <- err:
				return
			default:
				return
			}
		}
	}()

	wg.Wait()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errChan:
		return err
	default:
		// continue
	}

	if err := h.AccessTokenHelper.GenToken(ctx, req, resp); err != nil {
		return err
	}

	if err := h.RefreshTokenHelper.GenToken(ctx, req, resp); err != nil {
		return err
	}

	resp.Set(RedirectUri, req.GetRedirectUri())

	return nil
}

func (h *RefreshHandler) supportsTokenRequest(req TokenRequest) bool {
	return Exactly(req.GetGrantTypes(), spi.GrantTypeRefresh)
}