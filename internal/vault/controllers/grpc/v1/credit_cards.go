package v1

import (
	"context"
	"fmt"
	"regexp"

	"github.com/alukart32/yandex/practicum/passkee/internal/vault/models"
	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/creditcardpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func RegisterCreditCardsVaultService(srv *grpc.Server, provider sessionProvider, vault creditCardsVault) error {
	if srv == nil {
		return fmt.Errorf("no grpc server to register")
	}
	if provider == nil {
		return fmt.Errorf("no session provider")
	}
	if vault == nil {
		return fmt.Errorf("no vault")
	}

	creditcardpb.RegisterCreditCardsVaultServer(srv,
		&creditCardVaultService{
			sessProvider: provider,
			vault:        vault,
		},
	)
	return nil
}

type creditCardVaultService struct {
	creditcardpb.UnimplementedCreditCardsVaultServer

	sessProvider sessionProvider
	vault        creditCardsVault
}

type creditCardsVault interface {
	Save(context.Context, models.CreditCard) error
	Get(context.Context, models.ObjectMeta) (models.CreditCard, error)
	Index(ctx context.Context, userID string) ([]models.CreditCard, error)
	Update(context.Context, models.ObjectMeta, models.CreditCard) error
	Delete(context.Context, models.ObjectMeta) error
}

func (s *creditCardVaultService) AddCreditCard(ctx context.Context, in *creditcardpb.AddCreditCardRequest) (
	*emptypb.Empty, error) {
	session, err := s.sessProvider.SessionById(sessionFromCtx(ctx))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "session not found")
	}
	encrypter, err := session.DataEncrypter()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't prepare session: %v", err)
	}

	name, err := encrypter.Decrypt([]byte(in.Card.Name))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't process name from request: %v", err)
	}
	data, err := encrypter.Decrypt([]byte(in.Card.Data))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't process data from request: %v", err)
	}
	dataRegx := regexp.MustCompile(`([0-9]+):((0?[1-9]|1[012])\/[0-9]{4}):([0-9]{3})(:([A-Z]+)_([A-Z]+))?`)
	if !dataRegx.MatchString(string(data)) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid credit card format", err)
	}

	var notes []byte
	if in.Card.Notes != nil {
		notes, err = encrypter.Decrypt([]byte(*in.Card.Notes))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't process notes from request: %v", err)
		}
	}

	userID := userIDFromCtx(ctx)
	err = s.vault.Save(ctx, models.CreditCard{
		Meta: models.ObjectMeta{
			UserID: userID,
			Name:   name,
		},
		Data:  data,
		Notes: notes,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't save a new credit card: %v", err)
	}

	return &emptypb.Empty{}, nil
}

func (s *creditCardVaultService) GetCreditCard(ctx context.Context, in *creditcardpb.GetCreditCardRequest) (
	*creditcardpb.CreditCard, error) {
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
	creditCard, err := s.vault.Get(ctx, models.ObjectMeta{
		UserID: userID,
		Name:   recordName,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't find a credit card record: %v", err)
	}
	if creditCard.IsEmpty() {
		return nil, status.Error(codes.Unknown, "credit card record not found")
	}

	data, err := encrypter.Encrypt([]byte(creditCard.Data))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't prepare record data for response: %v", err)
	}
	var notes string
	if len(creditCard.Notes) != 0 {
		b, err := encrypter.Encrypt(creditCard.Notes)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't prepare record notes for response: %v", err)
		}
		notes = string(b)
	}

	return &creditcardpb.CreditCard{
		Name:  in.Name,
		Data:  string(data),
		Notes: &notes,
	}, nil
}

func (s *creditCardVaultService) IndexCreditCards(ctx context.Context, _ *emptypb.Empty) (
	*creditcardpb.IndexCreditCardsResponse, error) {
	records, err := s.vault.Index(ctx, userIDFromCtx(ctx))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't index credit cards: %v", err)
	}
	if len(records) == 0 {
		return &creditcardpb.IndexCreditCardsResponse{}, nil
	}

	session, err := s.sessProvider.SessionById(sessionFromCtx(ctx))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "session not found")
	}
	encrypter, err := session.DataEncrypter()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't prepare session: %v", err)
	}

	cards := make([]*creditcardpb.IndexCreditCardsResponse_CreditCard, len(records))
	for i, v := range records {
		name, err := encrypter.Encrypt(v.Meta.Name)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't prepare data for sending: %v", err)
		}
		cards[i] = &creditcardpb.IndexCreditCardsResponse_CreditCard{
			Name: string(name),
		}
	}
	return &creditcardpb.IndexCreditCardsResponse{Cards: cards}, nil
}

func (s *creditCardVaultService) UpdateCreditCard(ctx context.Context, in *creditcardpb.UpdateCreditCardRequest) (
	*emptypb.Empty, error) {
	if in.Card.Name == nil && in.Card.Data == nil && in.Card.Notes == nil {
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
	if len(*in.Card.Name) != 0 {
		b, err := encrypter.Decrypt([]byte(*in.Card.Name))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't process a new name from request: %v")
		}
		newName = b
	}
	var newData []byte
	if len(*in.Card.Data) != 0 {
		b, err := encrypter.Decrypt([]byte(*in.Card.Data))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't process new data from request: %v")
		}
		newData = b
	}
	dataRegx := regexp.MustCompile(`([0-9]+):((0?[1-9]|1[012])\/[0-9]{4}):([0-9]{3})(:([A-Z]+)_([A-Z]+))?`)
	if !dataRegx.MatchString(string(newData)) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid password pair format", err)
	}
	var newNotes []byte
	if len(*in.Card.Notes) != 0 {
		b, err := encrypter.Decrypt([]byte(*in.Card.Notes))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't process new notes from request: %v")
		}
		newNotes = b
	}

	userID := userIDFromCtx(ctx)
	err = s.vault.Update(ctx,
		models.ObjectMeta{
			UserID: userID,
			Name:   recordName,
		},
		models.CreditCard{
			Meta: models.ObjectMeta{
				Name: newName,
			},
			Data:  newData,
			Notes: newNotes,
		})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't reset credit card record: %v", err)
	}

	return &emptypb.Empty{}, nil
}

func (s *creditCardVaultService) DeleteCreditCard(ctx context.Context, in *creditcardpb.DeleteCreditCardRequest) (
	*emptypb.Empty, error) {
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
		return nil, status.Errorf(codes.Internal, "can't delete credit card record: %v", err)
	}
	return &emptypb.Empty{}, nil
}
