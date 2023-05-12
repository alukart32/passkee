package v1

import (
	"context"
	"encoding/base64"

	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/authpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func RegisterSessionService(srv *grpc.Server) {
	// TODO:
}

type sessionService struct {
	authpb.UnimplementedSessionServer

	conn connHandler
}

func (s *sessionService) Handshake(ctx context.Context, _ *emptypb.Empty) (*authpb.ServerSession, error) {
	sess, err := s.conn.InitSession()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "start session: %v", err)
	}

	md := metadata.Pairs("session_id", base64.StdEncoding.EncodeToString([]byte(sess.Id)))
	grpc.SetHeader(ctx, md)

	return &authpb.ServerSession{
		Id:  base64.StdEncoding.EncodeToString([]byte(sess.Id)),
		Key: sess.Base64Key(),
	}, nil
}

func (s *sessionService) Terminate(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	s.conn.TerminateSession(sessionFromCtx(ctx))
	return &emptypb.Empty{}, nil
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
	return sessionID
}
