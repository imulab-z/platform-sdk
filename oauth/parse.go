package oauth

import (
	"context"
	"github.com/imulab-z/platform-sdk/spi"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/url"
	"strings"
)

var (
	ErrMethodNotSupported = spi.ErrInvalidRequest("http method is not supported.")
)

type RequestParser interface {
	ParseAuthorizeRequest(ctx context.Context, r *http.Request, req AuthorizeRequest) error
	ParseTokenRequest(ctx context.Context, r *http.Request, req TokenRequest) error
}

func NewHttpRequestParser(lookup spi.ClientLookup) RequestParser {
	return &httpRequestParser{ClientLookup:lookup}
}

type httpRequestParser struct {
	ClientLookup	spi.ClientLookup
}

func (p *httpRequestParser) ParseAuthorizeRequest(ctx context.Context, r *http.Request, req AuthorizeRequest) error {
	var (
		values 	url.Values
		err 	error
	)

	switch r.Method {
	case http.MethodGet:
		values, err = url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			return err
		}
	default:
		return ErrMethodNotSupported
	}

	return p.parseAuthorizeRequest(ctx, values, req)
}

func (p *httpRequestParser) parseAuthorizeRequest(ctx context.Context, values url.Values, req AuthorizeRequest) error {
	logrus.WithFields(logrus.Fields{
		spi.ParamClientId: values.Get(spi.ParamClientId),
		spi.ParamResponseType: values.Get(spi.ParamResponseType),
		spi.ParamRedirectUri: values.Get(spi.ParamRedirectUri),
		spi.ParamScope: values.Get(spi.ParamScope),
		spi.ParamState: values.Get(spi.ParamState),
	}).Debug("received authorize request.")

	clientChan, errChan := make(chan spi.OAuthClient), make(chan error)
	defer close(clientChan)
	defer close(errChan)
	go func() {
		c, err := p.ClientLookup.FindById(ctx, values.Get(spi.ParamClientId))
		select {
		case <-ctx.Done():
			return
		default:
			if err != nil {
				errChan <- err
			} else {
				clientChan <- c
			}
		}
	}()

	req.addResponseTypes(strings.Split(values.Get(spi.ParamResponseType), " ")...)
	req.addScopes(strings.Split(values.Get(spi.ParamScope), " ")...)
	req.setState(values.Get(spi.ParamState))

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errChan:
		return err
	case c := <-clientChan:
		req.setClient(c)
	}

	if uri, err := SelectRedirectUri(values.Get(spi.ParamRedirectUri), req.GetClient().GetRedirectUris()); err != nil {
		return err
	} else {
		req.setRedirectUri(uri)
	}

	return nil
}

func (p *httpRequestParser) ParseTokenRequest(ctx context.Context, r *http.Request, req TokenRequest) error {
	panic("implement me")
}


