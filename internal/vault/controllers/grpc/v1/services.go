// Пакет v1 defines the v1 gRPC API services.
package v1

import (
	"context"

	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/conn"
	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/authpb"
	"google.golang.org/grpc/metadata"
)

type sessionProvider interface {
	SessionById(string) (conn.Session, error)
}

type connHandler interface {
	InitSession() (conn.Session, error)
	TerminateSession(id string)
}

// MethodsForAuthSkip returns a list of gRPC methods for auth skip.
func MethodsForAuthSkip() []string {
	skipMethods := []string{
		authpb.Auth_ServiceDesc.ServiceName,
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
