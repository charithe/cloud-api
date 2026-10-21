// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/failsafe-go/failsafe-go"
	"github.com/failsafe-go/failsafe-go/circuitbreaker"
)

var circuitBreaker failsafe.Executor[connect.ClientStream]

func init() {
	circuitBreaker = newCircuitBreaker()
}

func newUserAgentInterceptor(pdpVersion string) connect.ClientInterceptor {
	version := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Sum != "" {
			version = info.Main.Version
		} else {
			for _, bs := range info.Settings {
				if bs.Key == "vcs.revision" {
					version = bs.Value
				}
			}
		}
	}

	userAgent := fmt.Sprintf("cerbos-cloud-client/%s (%s; %s)", version, runtime.GOOS, runtime.GOARCH)

	return func(next connect.ClientFunc) connect.ClientFunc {
		return func(ctx context.Context, spec connect.Spec) (connect.ClientStream, error) {
			clientInfo, ok := connect.CallInfoForClientContext(ctx)
			if !ok {
				ctx, clientInfo = connect.NewClientContext(ctx)
			}

			clientInfo.RequestHeader().Set("User-Agent", userAgent)
			if pdpVersion != "" {
				clientInfo.RequestHeader().Set("X-Cerbos-PDP-Version", pdpVersion)
			}

			return next(ctx, spec)
		}
	}
}

func newAuthInterceptor(tokenSetter *tokenSetter) connect.ClientInterceptor {
	return func(next connect.ClientFunc) connect.ClientFunc {
		return func(ctx context.Context, spec connect.Spec) (connect.ClientStream, error) {
			clientInfo, ok := connect.CallInfoForClientContext(ctx)
			if !ok {
				ctx, clientInfo = connect.NewClientContext(ctx)
			}

			if err := tokenSetter.SetHeader(ctx, clientInfo.RequestHeader()); err != nil {
				return nil, err
			}

			return next(ctx, spec)
		}
	}
}

func newCircuitBreakerInterceptor(enabled *bool) connect.ClientInterceptor {
	return func(next connect.ClientFunc) connect.ClientFunc {
		return func(ctx context.Context, spec connect.Spec) (connect.ClientStream, error) {
			if !(*enabled) {
				return next(ctx, spec)
			}

			// This error shouldn't go through the circuit breaker because only other interceptors can produce an error at this stage.
			// Because the error here is always nil, the circuit breaker error streak gets broken and it never trips.
			stream, err := next(ctx, spec)
			if err != nil {
				return stream, err
			}

			return &circuitBreakerClientStream{cb: circuitBreaker, ClientStream: stream}, err
		}
	}
}

type circuitBreakerClientStream struct {
	cb failsafe.Executor[connect.ClientStream]
	connect.ClientStream
}

func (cbcs *circuitBreakerClientStream) Receive(msg any) error {
	_, err := cbcs.cb.Get(func() (connect.ClientStream, error) {
		return nil, cbcs.ClientStream.Receive(msg)
	})

	if errors.Is(err, circuitbreaker.ErrOpen) {
		return ErrTooManyFailures
	}
	return err
}

func newCircuitBreaker() failsafe.Executor[connect.ClientStream] {
	return failsafe.With(
		circuitbreaker.NewBuilder[connect.ClientStream]().
			WithFailureRateThreshold(0.6, 5, 15*time.Second). // open circuit if >=5 requests have been made in the last 15 seconds and >=60% of them have failed
			HandleIf(func(_ connect.ClientStream, err error) bool {
				if err == nil {
					return false
				}

				code := connect.CodeOf(err)
				switch code {
				case connect.CodeAborted, connect.CodeAlreadyExists, connect.CodeCanceled, connect.CodeDeadlineExceeded, connect.CodeFailedPrecondition:
					return false
				default:
					return true
				}
			}).
			Build(),
	)
}
