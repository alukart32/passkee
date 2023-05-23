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
	Get(ctx context.Context, username string) (models.User, error)
}

// basicAuth authenticates methods call using the basic authentication type.
func basicAuth(provider userProvider) authmd.AuthFunc {
	return func(ctx context.Context) (context.Context, error) {
		var newCtx = func(ctx context.Context, userID string) context.Context {
			md := metadata.New(map[string]string{
				"user_id":    userID,
				"session_id": sessionFromCtx(ctx),
			})
			return metadata.NewIncomingContext(ctx, md)
		}

		// Get auth basic header.
		rawToken, err := authmd.AuthFromMD(ctx, "basic")
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "basic header not found: %v", err)
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
		user, err := provider.Get(ctx, creds[0])
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "invalid auth: can't find user: %v", err)
		}
		if user.IsEmpty() {
			return nil, status.Error(codes.Unauthenticated, "invalid auth: user not found")
		} else {
			// Validate user credentials.
			creds := fmt.Sprintf("%v:%v", string(user.Username)[:], string(user.Password)[:])
			creds = base64.StdEncoding.EncodeToString([]byte(creds))
			if rawToken != creds {
				return nil, status.Errorf(codes.Unauthenticated, "invalid auth credentials")
			}
		}
		return newCtx(ctx, user.ID), nil
	}
}

func sessionFromCtx(ctx context.Context) string {
	var sessionID string
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		values := md.Get("session_id")
		if len(values) > 0 {
			sessionID = values[0]
		}
	}

	return sessionID
}
