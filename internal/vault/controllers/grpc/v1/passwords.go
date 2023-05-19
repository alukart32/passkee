package v1

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/alukart32/yandex/practicum/passkee/internal/vault/models"
	"github.com/alukart32/yandex/practicum/passkee/internal/vault/storage"
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
	Get(context.Context, models.ObjectMeta) (models.Password, error)
	Index(ctx context.Context, userID string) ([]models.Password, error)
	Reset(ctx context.Context, meta models.ObjectMeta, data models.Password) error
	Delete(ctx context.Context, meta models.ObjectMeta) error
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
		return nil, status.Error(codes.InvalidArgument, "invalid password pair format")
	}

	var notes []byte
	if len(in.Password.Notes) != 0 {
		notes, err = encrypter.Decrypt(in.Password.Notes)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't process notes from request: %v", err)
		}
	}

	err = s.vault.Save(ctx, models.Password{
		Meta: models.ObjectMeta{
			UserID: userIDFromCtx(ctx),
			Name:   name,
		},
		Data:  data,
		Notes: notes,
	})
	if err != nil {
		if errors.Is(storage.ErrNameUniqueViolation, err) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "can't save a new record: %v", err)
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
	pass, err := s.vault.Get(ctx, models.ObjectMeta{
		UserID: userID,
		Name:   recordName,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't find a password record: %v", err)
	}
	if pass.IsEmpty() {
		return nil, status.Error(codes.Unknown, "password record not found")
	}

	data, err := encrypter.Encrypt(pass.Data)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't prepare record data for response: %v", err)
	}
	var notes []byte
	if len(pass.Notes) != 0 {
		notes, err = encrypter.Encrypt(pass.Notes)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't prepare record notes for response: %v", err)
		}
	}

	return &passwordpb.Password{
		Name:  in.Name,
		Data:  data,
		Notes: notes,
	}, nil
}

func (s *passwordVaultService) IndexPasswords(ctx context.Context, _ *emptypb.Empty) (
	*passwordpb.IndexPasswordsResponse, error) {
	records, err := s.vault.Index(ctx, userIDFromCtx(ctx))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't index passwords: %v", err)
	}
	if len(records) == 0 {
		return &passwordpb.IndexPasswordsResponse{}, nil
	}

	session, err := s.sessProvider.SessionById(sessionFromCtx(ctx))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "session not found")
	}
	encrypter, err := session.DataEncrypter()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't prepare session: %v", err)
	}

	names := make([][]byte, len(records))
	for i, v := range records {
		name, err := encrypter.Encrypt(v.Meta.Name)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't prepare data for sending: %v", err)
		}
		names[i] = name
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
	if len(in.Password.Name) != 0 {
		newName, err = encrypter.Decrypt(in.Password.Name)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't process a new name from request: %v")
		}
	}
	var newData []byte
	if len(in.Password.Data) != 0 {
		newData, err = encrypter.Decrypt(in.Password.Data)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't process a new data from request: %v")
		}

		dataRegx := regexp.MustCompile(`^([0-9A-Za-z@#$%*_^\\]{1,15}):([0-9A-Za-z@#$%*_^\\]{1,15})$`)
		if !dataRegx.MatchString(string(newData)) {
			return nil, status.Error(codes.InvalidArgument, "invalid password pair format")
		}
	}

	var newNotes []byte
	if len(in.Password.Notes) != 0 {
		newNotes, err = encrypter.Decrypt(in.Password.Notes)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't process new notes from request: %v")
		}
	}

	userID := userIDFromCtx(ctx)
	err = s.vault.Reset(ctx,
		models.ObjectMeta{
			UserID: userID,
			Name:   recordName,
		},
		models.Password{
			Meta: models.ObjectMeta{
				Name: newName,
			},
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

	userID := userIDFromCtx(ctx)
	if err := s.vault.Delete(ctx, models.ObjectMeta{
		UserID: userID,
		Name:   recordName,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "can't delete password record: %v", err)
	}
	return &emptypb.Empty{}, nil
}
