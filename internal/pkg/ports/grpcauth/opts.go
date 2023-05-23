// Package grpcauth provides auth options for gRPC server.
package grpcauth

import (
	"context"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/selector"
)

// AuthOpts defines grpc server auth options.
type AuthOpts struct {
	Fn   auth.AuthFunc
	Skip selector.Matcher
}

// NewAuthOpts returns a new AuthOpts.
func NewAuthOpts(userProvider userProvider, passMethods []string) *AuthOpts {
	return &AuthOpts{
		Fn:   basicAuth(userProvider),
		Skip: selector.MatchFunc(skipSelector(passMethods)),
	}
}

// skipSelector skips method call to process by grpc server interceptor.
func skipSelector(passMethods []string) func(ctx context.Context, c interceptors.CallMeta) bool {
	return func(_ context.Context, c interceptors.CallMeta) bool {
		for _, v := range passMethods {
			if c.FullMethod() == v {
				return false
			}
		}
		return true
	}
}
