// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0
package bundle

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"

	apikeyv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/apikey/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/apikey/v1/apikeyv1connect"
)

const (
	AuthTokenHeader = "x-cerbos-auth" //nolint:gosec
	earlyExpiry     = 5 * time.Minute
)

var ErrAuthenticationFailed = errors.New("failed to authenticate: invalid credentials")

type authClient struct {
	accessToken  string
	expiresAt    time.Time
	apiKeyClient apikeyv1connect.ApiKeyServiceClient
	clientID     string
	clientSecret string
	mutex        sync.RWMutex
}

func newAuthClient(conf ClientConf, httpClient *http.Client, clientOptions ...connect.ClientOption) *authClient {
	return &authClient{
		apiKeyClient: apikeyv1connect.NewApiKeyServiceClient(httpClient, conf.APIEndpoint, clientOptions...),
		clientID:     conf.Credentials.ClientID,
		clientSecret: conf.Credentials.ClientSecret,
	}
}

func (a *authClient) SetAuthTokenHeader(ctx context.Context, headers http.Header) error {
	accessToken, err := a.authenticate(ctx)
	if err != nil {
		return err
	}

	headers.Set(AuthTokenHeader, accessToken)
	return nil
}

func (a *authClient) authenticate(ctx context.Context) (string, error) {
	a.mutex.RLock()
	accessToken, ok := a.currentAccessToken()
	a.mutex.RUnlock()
	if ok {
		return accessToken, nil
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	accessToken, ok = a.currentAccessToken()
	if ok {
		return accessToken, nil
	}

	response, err := a.apiKeyClient.IssueAccessToken(ctx, connect.NewRequest(&apikeyv1.IssueAccessTokenRequest{
		ClientId:     a.clientID,
		ClientSecret: a.clientSecret,
	}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeUnauthenticated {
			return "", ErrAuthenticationFailed
		}
		return "", fmt.Errorf("failed to authenticate: %w", err)
	}

	expiresIn := response.Msg.ExpiresIn.AsDuration()
	if expiresIn > earlyExpiry {
		expiresIn -= earlyExpiry
	}

	a.accessToken = response.Msg.AccessToken
	a.expiresAt = time.Now().Add(expiresIn)

	return a.accessToken, nil
}

func (a *authClient) currentAccessToken() (string, bool) {
	return a.accessToken, a.accessToken != "" && a.expiresAt.After(time.Now())
}
