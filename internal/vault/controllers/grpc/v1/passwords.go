package v1

import (
	"context"

	"github.com/alukart32/yandex/practicum/passkee/internal/vault/models"
	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/passwordspb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func RegisterPasswordsVaultService(srv *grpc.Server) {
	// TODO:
}

type passwordsVault interface {
	Save(models.Passwords) error
	Get(name string) (models.Passwords, error)
}

type passwordsVaultService struct {
	passwordspb.UnimplementedPasswordsVaultServer

	sessProvider sessionProvider
	vault        passwordsVault
}

func (s *passwordsVaultService) AddPassword(ctx context.Context, in *passwordspb.AddPasswordRequest) (*emptypb.Empty, error) {
	session, err := s.sessProvider.SessionById(sessionFromCtx(ctx))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "session not found")
	}
	encrypter, err := session.DataEncrypter()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't prepare session encrypter: %v", err)
	}

	name, err := encrypter.Decrypt([]byte(in.Password.Name))
	if err != nil {
		return nil, status.Error(codes.Internal, "can't decrypt a name from request")
	}

	data, err := encrypter.Decrypt([]byte(in.Password.Data))
	if err != nil {
		return nil, status.Error(codes.Internal, "can't decrypt a data from request")
	}

	var notes []byte
	if in.Password.Notes != nil {
		notes, err = encrypter.Decrypt([]byte(*in.Password.Notes))
		if err != nil {
			return nil, status.Error(codes.Internal, "can't decrypt notes from request")
		}
	}

	err = s.vault.Save(models.Passwords{
		UserID: userIDFromCtx(ctx),
		Name:   name,
		Data:   data,
		Notes:  notes,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't save a new password: %v", err)
	}

	return &emptypb.Empty{}, nil
}

func (s *passwordsVaultService) DeletePassword(ctx context.Context, in *passwordspb.DeletePasswordRequest) (*emptypb.Empty, error) {
	// TODO:
	return &emptypb.Empty{}, nil
}

func (s *passwordsVaultService) GetPassword(ctx context.Context, in *passwordspb.GetPasswordRequest) (*passwordspb.Password, error) {
	session, err := s.sessProvider.SessionById(sessionFromCtx(ctx))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "session not found")
	}
	encrypter, err := session.DataEncrypter()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't prepare session encrypter: %v", err)
	}

	name, err := encrypter.Decrypt([]byte(in.Name))
	if err != nil {
		return nil, status.Error(codes.Internal, "can't decrypt a name from request")
	}

	password, err := s.vault.Get(string(name))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't find a password record: %v", err)
	}
	if password.IsEmpty() {
		return nil, status.Error(codes.InvalidArgument, "password record not found")
	}

	data, err := encrypter.Encrypt(password.Data)
	if err != nil {
		return nil, status.Error(codes.Internal, "can't encrypt a record data for response")
	}

	var notes string
	if len(password.Notes) != 0 {
		notesBz, err := encrypter.Encrypt(password.Notes)
		if err != nil {
			return nil, status.Error(codes.Internal, "can't encrypt a record notes for response")
		}
		notes = string(notesBz)
	}

	return &passwordspb.Password{
		Name:  in.Name,
		Data:  string(data),
		Notes: &notes,
	}, nil
}

func (s *passwordsVaultService) IndexPasswords(ctx context.Context, in *emptypb.Empty) (
	*passwordspb.IndexPasswordsResponse,
	error) {
	// TODO:
	return &passwordspb.IndexPasswordsResponse{}, nil
}

func (s *passwordsVaultService) UpdatePassword(ctx context.Context, in *passwordspb.UpdatePasswordRequest) (
	*emptypb.Empty, error) {
	// TODO:
	return &emptypb.Empty{}, nil
}
