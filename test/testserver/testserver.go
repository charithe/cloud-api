// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package testserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/cerbos/cloud-api/base"
	"github.com/cerbos/cloud-api/credentials"
	apikeyv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/apikey/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/apikey/v1/apikeyv1connect"
	pdpv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/pdp/v1"
	"github.com/cerbos/cloud-api/hub"
	mockapikeyv1connect "github.com/cerbos/cloud-api/test/mocks/genpb/cerbos/cloud/apikey/v1/apikeyv1connect"
)

func ConnectOptions() []connecthttp.Option {
	return []connecthttp.Option{connecthttp.WithCompressMinBytes(1024)}
}

func ConnectInterceptors() []connect.ServerInterceptor {
	return []connect.ServerInterceptor{newAuthCheck()}
}

func Start(t *testing.T, handlers []func(*connect.Server), creds *credentials.Credentials) (*mockapikeyv1connect.ApiKeyServiceHandler, *hub.Hub) {
	t.Helper()

	mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
	apiKeyServer := connect.NewServer(NewLogRequests(t))
	apikeyv1connect.RegisterApiKeyServiceHandler(apiKeyServer, mockAPIKeySvc)

	otherServer := connect.NewServer(NewLogRequests(t), newAuthCheck())
	for _, handler := range handlers {
		handler(otherServer)
	}

	mux := http.NewServeMux()
	connecthttp.Mount(mux, apiKeyServer)
	connecthttp.Mount(mux, otherServer)

	s := httptest.NewUnstartedServer(mux)
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(true)
	s.Config.Protocols = protocols
	s.EnableHTTP2 = true
	s.StartTLS()

	t.Cleanup(s.Close)

	h := newHub(t, s, creds)
	return mockAPIKeySvc, h
}

func newHub(t *testing.T, server *httptest.Server, creds *credentials.Credentials) *hub.Hub {
	t.Helper()

	cert := server.Certificate()
	var tlsConf *tls.Config
	if cert != nil {
		certPool := x509.NewCertPool()
		certPool.AddCert(cert)
		tlsConf = &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true, //nolint:staticcheck
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			NextProtos: []string{"h2"},
			RootCAs:    certPool,
		}
	}

	url := server.URL
	pdpIdentifer := &pdpv1.Identifier{
		Instance: "instance",
		Version:  "0.34.0",
	}
	h, err := hub.New(base.ClientConf{
		Credentials:       creds,
		BootstrapEndpoint: url,
		APIEndpoint:       url,
		PDPIdentifier:     pdpIdentifer,
		RetryWaitMin:      10 * time.Millisecond,
		RetryWaitMax:      30 * time.Millisecond,
		RetryMaxAttempts:  2,
		Logger:            testr.NewWithOptions(t, testr.Options{Verbosity: 4}),
		TLS:               tlsConf,
	})
	require.NoError(t, err, "Failed to create hub instance")

	return h
}

const expectedAuthToken = "access-token"

func newAuthCheck() connect.ServerInterceptor {
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			info, _ := connect.CallInfoForServerContext(ctx)
			if info.RequestHeader().Get(base.AuthTokenHeader) != expectedAuthToken {
				return connect.NewError(connect.CodeUnauthenticated, "invalid or missing access token")
			}

			return next(ctx, spec, stream)
		}
	}
}

func NewLogRequests(t *testing.T) connect.ServerInterceptor {
	t.Helper()

	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			t.Logf("REQUEST: %s", spec.Procedure)
			if err := next(ctx, spec, stream); err != nil {
				t.Logf("ERROR for %s: %+v", spec.Procedure, err)
				return err
			}

			return nil
		}
	}
}

func ExpectAPIKeySuccess(t *testing.T, mockAPIKeySvc *mockapikeyv1connect.ApiKeyServiceHandler) {
	t.Helper()

	mockAPIKeySvc.EXPECT().
		IssueAccessToken(mock.Anything, MatchIssueAccessTokenRequest()).
		Return(&apikeyv1.IssueAccessTokenResponse{
			AccessToken: expectedAuthToken,
			ExpiresIn:   durationpb.New(1 * time.Minute),
		}, nil)
}

func ExpectAPIKeyFailure(t *testing.T, mockAPIKeySvc *mockapikeyv1connect.ApiKeyServiceHandler) {
	t.Helper()

	mockAPIKeySvc.EXPECT().
		IssueAccessToken(mock.Anything, MatchIssueAccessTokenRequest()).
		Return(nil, connect.NewError(connect.CodeUnauthenticated, "unauthenticated")).
		Once()
}

func MatchIssueAccessTokenRequest() any {
	return mock.MatchedBy(func(req *apikeyv1.IssueAccessTokenRequest) bool {
		return req.GetClientId() == "client-id" && req.GetClientSecret() == "client-secret"
	})
}
