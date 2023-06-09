package v1

import (
	"context"
	"encoding/base64"

	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/conn"
	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/authpb"
	"google.golang.org/grpc/metadata"
)

// sessionProvider defines the provider of current sessions.
type sessionProvider interface {
	SessionById(string) (conn.Session, error)
}

// connHandler defines the client session handler.
type connHandler interface {
	InitSession() (conn.Session, error)
	TerminateSession(id string)
}

// MethodsForAuthSkip returns a list of gRPC methods for auth skip.
func MethodsForAuthSkip() []string {
	skipMethods := []string{
		authpb.Auth_LogOn_FullMethodName,
		authpb.Session_Handshake_FullMethodName,
		authpb.Session_Terminate_FullMethodName,
	}
	return skipMethods
}

// userIDFromCtx gets userID from the context of the method request.
func userIDFromCtx(ctx context.Context) string {
	var userID string
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		values := md.Get("user_id")
		if len(values) > 0 {
			userID = values[0]
		}
	}
	return userID
}

// sessionFromCtx gets sessionID from the context of the method request.
func sessionFromCtx(ctx context.Context) string {
	var sessionID string
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		values := md.Get("session_id")
		if len(values) > 0 {
			sessionID = values[0]
		}
	}

	id, err := base64.StdEncoding.DecodeString(sessionID)
	if err != nil {
		return ""
	}

	return string(id)
}
