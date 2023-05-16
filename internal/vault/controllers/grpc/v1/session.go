package v1

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/authpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

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

type sessionService struct {
	authpb.UnimplementedSessionServer

	conn connHandler
}

func (s *sessionService) Handshake(ctx context.Context, _ *emptypb.Empty) (*authpb.ServerSession, error) {
	sess, err := s.conn.InitSession()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't start a new session: %v", err)
	}

	md := metadata.Pairs("session_id", base64.StdEncoding.EncodeToString([]byte(sess.Id)))
	grpc.SetHeader(ctx, md)

	return &authpb.ServerSession{
		Id:  base64.StdEncoding.EncodeToString([]byte(sess.Id)),
		Key: sess.Base64Key(),
	}, nil
}

func (s *sessionService) Terminate(ctx context.Context, in *authpb.TerminateRequest) (*emptypb.Empty, error) {
	s.conn.TerminateSession(in.Id)
	return &emptypb.Empty{}, nil
}
