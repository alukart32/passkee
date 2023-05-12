package grpcauth

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/alukart32/yandex/practicum/passkee/internal/vault/models"
	authmd "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type userProvider interface {
	Get(string) models.User
}

// basicAuth authenticates methods call using the basic authentication type.
func basicAuth(provider userProvider) authmd.AuthFunc {
	return func(ctx context.Context) (context.Context, error) {
		var ctxWithUserID = func(ctx context.Context, userID string) context.Context {
			md := metadata.New(map[string]string{"user_id": userID})
			return metadata.NewIncomingContext(ctx, md)
		}

		// Get auth basic header.
		rawToken, err := authmd.AuthFromMD(ctx, "basic")
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "no basic header found: %v", err)
		}
		token, err := base64.StdEncoding.DecodeString(rawToken)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "can't parse auth basic")
		}

		// username:password
		creds := strings.Split(string(token), ":")
		if len(creds[0]) == 0 || len(creds[1]) == 0 {
			return ctx, status.Errorf(codes.Unauthenticated, "invalid auth credentials format")
		}

		// Find user.
		user := provider.Get(creds[0])
		if user.IsEmpty() {
			return nil, status.Error(codes.Unauthenticated, "invalid auth credentials")
		} else {
			// Validate user credentials.
			creds := fmt.Sprintf("%v:%v", user.Login, user.Password)
			creds = base64.StdEncoding.EncodeToString([]byte(creds))
			if rawToken != creds {
				return nil, status.Errorf(codes.Unauthenticated, "invalid auth credentials")
			}
		}
		return ctxWithUserID(ctx, user.ID), nil
	}
}
