package v1

import (
	"context"
	"fmt"
	"regexp"

	"github.com/alukart32/yandex/practicum/passkee/internal/vault/models"
	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/passwordpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func RegisterPasswordsVaultService(srv *grpc.Server, sess sessionProvider, vault passwordsVault) error {
	if srv == nil {
		return fmt.Errorf("no grpc server to register")
	}
	if sess == nil {
		return fmt.Errorf("no session provider")
	}
	if vault == nil {
		return fmt.Errorf("no vault")
	}

	passwordpb.RegisterPasswordsVaultServer(srv,
		&passwordVaultService{
			sessProvider: sess,
			vault:        vault,
		},
	)
	return nil
}

type passwordVaultService struct {
	passwordpb.UnimplementedPasswordsVaultServer

	sessProvider sessionProvider
	vault        passwordsVault
}
type passwordsVault interface {
	Save(context.Context, models.Password) error
	GetByName(ctx context.Context, userID string, name string) (models.Password, error)
	Index(ctx context.Context, userID string) ([]models.Password, error)
	Reset(ctx context.Context, userID string, name string, p models.Password) error
	Delete(ctx context.Context, userID string, name string) error
}

func (s *passwordVaultService) AddPassword(ctx context.Context, in *passwordpb.AddPasswordRequest) (*emptypb.Empty, error) {
	session, err := s.sessProvider.SessionById(sessionFromCtx(ctx))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "session not found")
	}
	encrypter, err := session.DataEncrypter()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't prepare session: %v", err)
	}

	name, err := encrypter.Decrypt([]byte(in.Password.Name))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't process name from request: %v", err)
	}
	data, err := encrypter.Decrypt([]byte(in.Password.Data))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't process data from request: %v", err)
	}
	dataRegx := regexp.MustCompile(`^([0-9A-Za-z@#$%*_^\\]{1,15}):([0-9A-Za-z@#$%*_^\\]{1,15})$`)
	if !dataRegx.MatchString(string(data)) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid password pair format", err)
	}

	var notes []byte
	if in.Password.Notes != nil {
		notes, err = encrypter.Decrypt([]byte(*in.Password.Notes))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't process notes from request: %v", err)
		}
	}

	err = s.vault.Save(ctx, models.Password{
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

func (s *passwordVaultService) GetPassword(ctx context.Context, in *passwordpb.GetPasswordRequest) (*passwordpb.Password, error) {
	session, err := s.sessProvider.SessionById(sessionFromCtx(ctx))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "session not found")
	}
	encrypter, err := session.DataEncrypter()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't prepare session: %v", err)
	}

	recordName, err := encrypter.Decrypt([]byte(in.Name))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't process record name from request: %v", err)
	}

	userID := userIDFromCtx(ctx)
	password, err := s.vault.GetByName(ctx, userID, string(recordName))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't find a password record: %v", err)
	}
	if password.IsEmpty() {
		return nil, status.Error(codes.Unknown, "password record not found")
	}

	data, err := encrypter.Encrypt([]byte(password.Data))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't prepare record data for response: %v", err)
	}
	var notes string
	if len(password.Notes) != 0 {
		notesBz, err := encrypter.Encrypt([]byte(password.Notes))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't prepare record notes for response: %v", err)
		}
		notes = string(notesBz)
	}

	return &passwordpb.Password{
		Name:  in.Name,
		Data:  string(data),
		Notes: &notes,
	}, nil
}

func (s *passwordVaultService) IndexPasswords(ctx context.Context, in *emptypb.Empty) (
	*passwordpb.IndexPasswordsResponse, error) {
	records, err := s.vault.Index(ctx, userIDFromCtx(ctx))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't index passwords: %v", err)
	}

	session, err := s.sessProvider.SessionById(sessionFromCtx(ctx))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "session not found")
	}
	encrypter, err := session.DataEncrypter()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't prepare session: %v", err)
	}

	names := make([]string, len(records))
	for i, v := range records {
		name, err := encrypter.Encrypt([]byte(v.Name))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't prepare data for sending: %v", err)
		}
		names[i] = string(name)
	}
	return &passwordpb.IndexPasswordsResponse{Names: names}, nil
}

func (s *passwordVaultService) ResetPassword(ctx context.Context, in *passwordpb.ResetPasswordRequest) (*emptypb.Empty, error) {
	if in.Password.Name == nil && in.Password.Data == nil && in.Password.Notes == nil {
		return nil, status.Errorf(codes.InvalidArgument, "nothing to update")
	}

	session, err := s.sessProvider.SessionById(sessionFromCtx(ctx))
	if err != nil {
		return nil, status.Error(codes.Internal, "session not found")
	}
	encrypter, err := session.DataEncrypter()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't prepare session: %v", err)
	}

	recordName, err := encrypter.Decrypt([]byte(in.Name))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't process record name from request: %v")
	}

	var newName []byte
	if len(*in.Password.Name) != 0 {
		b, err := encrypter.Decrypt([]byte(*in.Password.Name))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't process a new name from request: %v")
		}
		newName = b
	}
	var newData []byte
	if len(*in.Password.Data) != 0 {
		b, err := encrypter.Decrypt([]byte(*in.Password.Data))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't process a new data from request: %v")
		}
		newData = b
	}
	dataRegx := regexp.MustCompile(`^([0-9A-Za-z@#$%*_^\\]{1,15}):([0-9A-Za-z@#$%*_^\\]{1,15})$`)
	if !dataRegx.MatchString(string(newData)) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid password pair format", err)
	}
	var newNotes []byte
	if len(*in.Password.Notes) != 0 {
		b, err := encrypter.Decrypt([]byte(*in.Password.Notes))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't process new notes from request: %v")
		}
		newNotes = b
	}

	err = s.vault.Reset(ctx,
		userIDFromCtx(ctx),
		string(recordName),
		models.Password{
			Name:  newName,
			Data:  newData,
			Notes: newNotes,
		})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't reset password record: %v", err)
	}

	return &emptypb.Empty{}, nil
}

func (s *passwordVaultService) DeletePassword(ctx context.Context, in *passwordpb.DeletePasswordRequest) (*emptypb.Empty, error) {
	session, err := s.sessProvider.SessionById(sessionFromCtx(ctx))
	if err != nil {
		return nil, status.Error(codes.Internal, "session not found")
	}
	encrypter, err := session.DataEncrypter()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't prepare session: %v", err)
	}

	recordName, err := encrypter.Decrypt([]byte(in.Name))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't process record name from request: %v")
	}

	if err := s.vault.Delete(ctx, userIDFromCtx(ctx), string(recordName)); err != nil {
		return nil, status.Errorf(codes.Internal, "can't delete password record: %v", err)
	}
	return &emptypb.Empty{}, nil
}
