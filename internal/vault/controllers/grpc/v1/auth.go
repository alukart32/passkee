package v1

import (
	"context"
	"fmt"

	"github.com/alukart32/yandex/practicum/passkee/internal/vault/models"
	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/authpb"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func RegisterAuthService(srv *grpc.Server, sess sessionProvider, saver userSaver) error {
	if srv == nil {
		return fmt.Errorf("no grpc server to register")
	}
	if sess == nil {
		return fmt.Errorf("no session provider")
	}
	if saver == nil {
		return fmt.Errorf("no user saver")
	}

	authpb.RegisterAuthServer(srv,
		&authService{
			sessProvider: sess,
			userSaver:    saver,
		},
	)
	return nil
}

type authService struct {
	authpb.UnimplementedAuthServer

	sessProvider sessionProvider
	userSaver    userSaver
}
type userSaver interface {
	Save(context.Context, models.User) error
}

func (s *authService) LogOn(ctx context.Context, in *authpb.LogOnRequest) (*emptypb.Empty, error) {
	session, err := s.sessProvider.SessionById(sessionFromCtx(ctx))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "session not found")
	}
	encrypter, err := session.DataEncrypter()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't prepare session: %v", err)
	}

	username, err := encrypter.Decrypt(in.Username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't process username from request: %v", err)
	}

	password, err := encrypter.Decrypt(in.Password)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't process password from request: %v", err)
	}

	err = s.userSaver.Save(ctx, models.User{
		ID:       uuid.New().String(),
		Username: username,
		Password: password,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't save a new user: %v", err)
	}

	return &emptypb.Empty{}, nil
}
