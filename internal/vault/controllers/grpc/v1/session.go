package v1

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/authpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// RegisterSessionService registers authpb.UnimplementedSessionServer implementation.
func RegisterSessionService(srv *grpc.Server, conn connHandler) error {
	if srv == nil {
		return fmt.Errorf("no grpc server to register")
	}
	if conn == nil {
		return fmt.Errorf("no connection handler")
	}

	authpb.RegisterSessionServer(srv,
		&sessionService{
			conn: conn,
		},
	)
	return nil
}

// sessionService is an implementation of authpb.UnimplementedSessionServer.
type sessionService struct {
	authpb.UnimplementedSessionServer

	conn connHandler
}

// Handshake creates a new session with the client. A unique symmetric message encryption key is created.
func (s *sessionService) Handshake(ctx context.Context, _ *emptypb.Empty) (*authpb.ServerSession, error) {
	sess, err := s.conn.InitSession()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't start a new session: %v", err)
	}

	return &authpb.ServerSession{
		Id:  base64.StdEncoding.EncodeToString([]byte(sess.Id)),
		Key: sess.Base64Key(),
	}, nil
}

// Terminate ends the client session.
func (s *sessionService) Terminate(ctx context.Context, in *authpb.TerminateRequest) (*emptypb.Empty, error) {
	id, err := base64.StdEncoding.DecodeString(in.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't terminate session: %v", err)
	}

	s.conn.TerminateSession(string(id))
	return &emptypb.Empty{}, nil
}
