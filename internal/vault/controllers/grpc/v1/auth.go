package v1

import (
	"context"

	"github.com/alukart32/yandex/practicum/passkee/internal/vault/models"
	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/authpb"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func RegisterAuthService(srv *grpc.Server) {
	// TODO:
}

type userSaver interface {
	Save(models.User) error
}

type authService struct {
	authpb.UnimplementedAuthServer

	sessProvider sessionProvider
	userSaver    userSaver
}

func (s *authService) LogOn(ctx context.Context, in *authpb.LogOnRequest) (*emptypb.Empty, error) {
	session, err := s.sessProvider.SessionById(sessionFromCtx(ctx))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "session not found")
	}
	encrypter, err := session.DataEncrypter()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't prepare session encrypter: %v", err)
	}

	username, err := encrypter.Decrypt(in.Username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't decrypt username: %v", err)
	}

	password, err := encrypter.Decrypt(in.Password)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't decrypt password: %v", err)
	}

	err = s.userSaver.Save(models.User{
		ID:       uuid.New().String(),
		Login:    username,
		Password: password,
	})
	if err != nil {
		// TODO: check username unique violation
		return &emptypb.Empty{}, nil
	}

	return &emptypb.Empty{}, nil
}
