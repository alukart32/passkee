package v1

import (
	"context"
	"fmt"
	"log"
	"net"
	"testing"

	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/conn"
	"github.com/alukart32/yandex/practicum/passkee/internal/vault/models"
	"github.com/alukart32/yandex/practicum/passkee/internal/vault/storage"
	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/creditcardpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

type creditCardsVaultMock struct {
	SaveFn   func(context.Context, models.CreditCard) error
	GetFn    func(context.Context, models.ObjectMeta) (models.CreditCard, error)
	IndexFn  func(ctx context.Context, userID string) ([]models.CreditCard, error)
	UpdateFn func(ctx context.Context, meta models.ObjectMeta, data models.CreditCard) error
	DeleteFn func(ctx context.Context, meta models.ObjectMeta) error
}

func (m *creditCardsVaultMock) Save(ctx context.Context, c models.CreditCard) error {
	if m != nil && m.SaveFn != nil {
		return m.SaveFn(ctx, c)
	}
	return fmt.Errorf("can't save a new credit card")
}

func (m *creditCardsVaultMock) Get(ctx context.Context, meta models.ObjectMeta) (models.CreditCard, error) {
	if m != nil && m.GetFn != nil {
		return m.GetFn(ctx, meta)
	}
	return models.CreditCard{}, fmt.Errorf("can't get a credit card")
}

func (m *creditCardsVaultMock) Index(ctx context.Context, userID string) ([]models.CreditCard, error) {
	if m != nil && m.IndexFn != nil {
		return m.IndexFn(ctx, userID)
	}
	return []models.CreditCard{}, fmt.Errorf("can't index credit cards")
}

func (m *creditCardsVaultMock) Update(ctx context.Context, meta models.ObjectMeta, data models.CreditCard) error {
	if m != nil && m.UpdateFn != nil {
		return m.UpdateFn(ctx, meta, data)
	}
	return fmt.Errorf("can't update credit card")
}

func (m *creditCardsVaultMock) Delete(ctx context.Context, meta models.ObjectMeta) error {
	if m != nil && m.DeleteFn != nil {
		return m.DeleteFn(ctx, meta)
	}
	return fmt.Errorf("can't delete credit card")
}

func TestCreditCardsService_AddCreditCard(t *testing.T) {
	// Prepare encrypter.
	key := "qlpdne07d7c2ut77qth9792ct7ah16oa"
	enc, err := testDataEncrypter(key)
	require.NoError(t, err)

	type creditCard struct {
		name  string
		data  string
		notes string
	}
	type services struct {
		sessProvider sessionProvider
		vault        creditCardsVault
	}
	type want struct {
		code codes.Code
	}
	tests := []struct {
		want want
		serv services
		req  creditCard
		name string
	}{
		{
			name: "Session not found, status code: Internal",
			req: creditCard{
				name:  "card",
				data:  "4960148153718504:02/2025:906:SURENAME_NAME",
				notes: "notes",
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{},
				vault:        &creditCardsVaultMock{},
			},
		},
		{
			name: "Corrupted session encrypter, status code: Internal",
			req: creditCard{
				name:  "card",
				data:  "4960148153718504:02/2025:906:SURENAME_NAME",
				notes: "notes",
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(""))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &creditCardsVaultMock{},
			},
		},
		{
			name: "Valid credit card, status code: Ok",
			req: creditCard{
				name:  "card",
				data:  "4960148153718504:02/2025:906:SURENAME_NAME",
				notes: "notes",
			},
			want: want{
				code: codes.OK,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &creditCardsVaultMock{
					SaveFn: func(_ context.Context, _ models.CreditCard) error {
						return nil
					},
				},
			},
		},
		{
			name: "Invalid format, status code: Internal",
			req: creditCard{
				name:  "card",
				data:  "4960148153718504:906:02/2025",
				notes: "notes",
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{},
				vault:        &creditCardsVaultMock{},
			},
		},
		{
			name: "Not unique username, status code: InvalidArgument",
			req: creditCard{
				name:  "card",
				data:  "4960148153718504:02/2025:906:SURENAME_NAME",
				notes: "notes",
			},
			want: want{
				code: codes.InvalidArgument,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &creditCardsVaultMock{
					SaveFn: func(_ context.Context, _ models.CreditCard) error {
						return storage.ErrNameUniqueViolation
					},
				},
			},
		},
		{
			name: "Can't save valid card, status code: Internal",
			req: creditCard{
				name:  "card",
				data:  "4960148153718504:02/2025:906:SURENAME_NAME",
				notes: "notes",
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &creditCardsVaultMock{
					SaveFn: func(_ context.Context, _ models.CreditCard) error {
						return fmt.Errorf("can't save")
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, closer :=
				cardServiceClient(context.Background(), tt.serv.sessProvider, tt.serv.vault)
			defer closer()

			name, err := enc.Encrypt([]byte(tt.req.name))
			require.NoError(t, err)
			data, err := enc.Encrypt([]byte(tt.req.data))
			require.NoError(t, err)
			notes, err := enc.Encrypt([]byte(tt.req.notes))
			require.NoError(t, err)

			_, err = client.AddCreditCard(context.Background(), &creditcardpb.AddCreditCardRequest{
				Card: &creditcardpb.CreditCard{
					Name:  name,
					Data:  data,
					Notes: notes,
				},
			})
			if err != nil {
				if e, ok := status.FromError(err); ok {
					assert.EqualValues(t, tt.want.code, e.Code(),
						"Expected status code: %d, got %d", tt.want.code, e.Code())
					return
				} else {
					t.Fatalf("failed to parse: %v", err)
				}
			}
		})
	}
}

func TestCreditCardsService_UpdateCreditCard(t *testing.T) {
	// Prepare encrypter.
	key := "qlpdne07d7c2ut77qth9792ct7ah16oa"
	enc, err := testDataEncrypter(key)
	require.NoError(t, err)

	type creditCard struct {
		name     string
		newName  string
		newData  string
		newNotes string
	}
	type services struct {
		sessProvider sessionProvider
		vault        creditCardsVault
	}
	type want struct {
		code codes.Code
	}
	tests := []struct {
		want want
		serv services
		req  creditCard
		name string
	}{
		{
			name: "Session not found, status code: Internal",
			req: creditCard{
				name:     "card",
				newName:  "card2",
				newData:  "4960148153718504:02/2025:906:SURENAME_NAME",
				newNotes: "notes",
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{},
				vault:        &creditCardsVaultMock{},
			},
		},
		{
			name: "Corrupted session encrypter, status code: Internal",
			req: creditCard{
				name:     "card",
				newName:  "card2",
				newData:  "4960148153718504:02/2025:906:SURENAME_NAME",
				newNotes: "notes",
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(""))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &creditCardsVaultMock{},
			},
		},
		{
			name: "Valid password, status code: Ok",
			req: creditCard{
				name:     "card",
				newName:  "card2",
				newData:  "4960148153718504:02/2025:906:SURENAME_NAME",
				newNotes: "notes",
			},
			want: want{
				code: codes.OK,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &creditCardsVaultMock{
					UpdateFn: func(_ context.Context, _ models.ObjectMeta, _ models.CreditCard) error {
						return nil
					},
				},
			},
		},
		{
			name: "Nothing to update, status code: InvalidArgument",
			req: creditCard{
				name: "card",
			},
			want: want{
				code: codes.InvalidArgument,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &creditCardsVaultMock{
					UpdateFn: func(_ context.Context, _ models.ObjectMeta, _ models.CreditCard) error {
						return nil
					},
				},
			},
		},
		{
			name: "Invalid card format, status code: InvalidArgument",
			req: creditCard{
				name:     "card",
				newName:  "card2",
				newData:  "4960148153718504:906:SURENAME_NAME",
				newNotes: "notes",
			},
			want: want{
				code: codes.InvalidArgument,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &creditCardsVaultMock{},
			},
		},
		{
			name: "Can't update credit card, status code: Internal",
			req: creditCard{
				name:     "card",
				newName:  "card2",
				newData:  "4960148153718504:02/2025:906:SURENAME_NAME",
				newNotes: "notes",
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &creditCardsVaultMock{
					UpdateFn: func(_ context.Context, _ models.ObjectMeta, _ models.CreditCard) error {
						return fmt.Errorf("can't update")
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, closer :=
				cardServiceClient(context.Background(), tt.serv.sessProvider, tt.serv.vault)
			defer closer()

			name, err := enc.Encrypt([]byte(tt.req.name))
			require.NoError(t, err)

			var newName []byte
			if len(tt.req.newName) != 0 {
				newName, err = enc.Encrypt([]byte(tt.req.newName))
				require.NoError(t, err)
			}
			var newData []byte
			if len(tt.req.newData) != 0 {
				newData, err = enc.Encrypt([]byte(tt.req.newData))
				require.NoError(t, err)
			}
			var newNotes []byte
			if len(tt.req.newNotes) != 0 {
				newNotes, err = enc.Encrypt([]byte(tt.req.newNotes))
				require.NoError(t, err)
			}

			_, err = client.UpdateCreditCard(context.Background(), &creditcardpb.UpdateCreditCardRequest{
				Name: name,
				Card: &creditcardpb.UpdateCreditCardRequest_CreditCard{
					Name:  newName,
					Data:  newData,
					Notes: newNotes,
				},
			})
			if err != nil {
				if e, ok := status.FromError(err); ok {
					assert.EqualValues(t, tt.want.code, e.Code(),
						"Expected status code: %d, got %d", tt.want.code, e.Code())
					return
				} else {
					t.Fatalf("failed to parse: %v", err)
				}
			}
		})
	}
}

func TestCreditCardsService_GetCreditCards(t *testing.T) {
	// Prepare encrypter.
	key := "qlpdne07d7c2ut77qth9792ct7ah16oa"
	enc, err := testDataEncrypter(key)
	require.NoError(t, err)

	type services struct {
		sessProvider sessionProvider
		vault        creditCardsVault
	}
	type want struct {
		data *creditcardpb.CreditCard
		code codes.Code
	}
	tests := []struct {
		want       want
		serv       services
		recordName string
		name       string
	}{
		{
			name:       "Session not found, status code: Internal",
			recordName: "card",
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{},
				vault:        &creditCardsVaultMock{},
			},
		},
		{
			name:       "Corrupted session encrypter, status code: Internal",
			recordName: "card",
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(""))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &creditCardsVaultMock{},
			},
		},
		{
			name:       "Return credit card, status code: Ok",
			recordName: "card",
			want: want{
				data: &creditcardpb.CreditCard{
					Name:  []byte("pass"),
					Data:  []byte("4960148153718504:02/2025:906:SURENAME_NAME"),
					Notes: []byte("notes"),
				},
				code: codes.OK,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &creditCardsVaultMock{
					GetFn: func(_ context.Context, om models.ObjectMeta) (models.CreditCard, error) {
						return models.CreditCard{
							Meta: om,
							Data: []byte("4960148153718504:02/2025:906:SURENAME_NAME"),
						}, nil
					},
				},
			},
		},
		{
			name:       "No such credit card, status code: Unknown",
			recordName: "card",
			want: want{
				data: &creditcardpb.CreditCard{
					Name:  []byte("pass"),
					Data:  []byte("4960148153718504:02/2025:906:SURENAME_NAME"),
					Notes: []byte("notes"),
				},
				code: codes.Unknown,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &creditCardsVaultMock{
					GetFn: func(_ context.Context, om models.ObjectMeta) (models.CreditCard, error) {
						return models.CreditCard{}, nil
					},
				},
			},
		},
		{
			name:       "Can't get credit card, status code: Internal",
			recordName: "card",
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &creditCardsVaultMock{
					SaveFn: func(_ context.Context, _ models.CreditCard) error {
						return fmt.Errorf("can't get")
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, closer :=
				cardServiceClient(context.Background(), tt.serv.sessProvider, tt.serv.vault)
			defer closer()

			name, err := enc.Encrypt([]byte(tt.recordName))
			require.NoError(t, err)

			resp, err := client.GetCreditCard(context.Background(), &creditcardpb.GetCreditCardRequest{
				Name: name,
			})
			if err != nil {
				if e, ok := status.FromError(err); ok {
					assert.EqualValues(t, tt.want.code, e.Code(),
						"Expected status code: %d, got %d", tt.want.code, e.Code())
					return
				} else {
					t.Fatalf("failed to parse: %v", err)
				}
			}

			data, err := enc.Decrypt(resp.Data)
			require.NoError(t, err)
			assert.EqualValues(t, tt.want.data.Data, data)

			if len(resp.Notes) != 0 {
				notes, err := enc.Decrypt(resp.Notes)
				require.NoError(t, err)
				assert.EqualValues(t, tt.want.data.Notes, notes)
			}
		})
	}
}

func TestCreditCArdsService_IndexCreditCards(t *testing.T) {
	// Prepare encrypter.
	key := "qlpdne07d7c2ut77qth9792ct7ah16oa"
	enc, err := testDataEncrypter(key)
	require.NoError(t, err)

	type services struct {
		sessProvider sessionProvider
		vault        creditCardsVault
	}
	type want struct {
		data *creditcardpb.IndexCreditCardsResponse
		code codes.Code
	}
	tests := []struct {
		want want
		serv services
		name string
	}{
		{
			name: "Session not found, status code: Internal",
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{},
				vault:        &creditCardsVaultMock{},
			},
		},
		{
			name: "Corrupted session encrypter, status code: Internal",
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(""))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &creditCardsVaultMock{},
			},
		},
		{
			name: "Return credit cards, status code: Ok",
			want: want{
				data: &creditcardpb.IndexCreditCardsResponse{
					Names: [][]byte{[]byte("c_1"), []byte("c_2"), []byte("c_3")},
				},
				code: codes.OK,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &creditCardsVaultMock{
					IndexFn: func(ctx context.Context, userID string) ([]models.CreditCard, error) {
						records := []models.CreditCard{
							{
								Meta: models.ObjectMeta{
									Name: []byte("c_1"),
								},
							},
							{
								Meta: models.ObjectMeta{
									Name: []byte("c_2"),
								},
							},
							{
								Meta: models.ObjectMeta{
									Name: []byte("c_3"),
								},
							},
						}
						return records, nil
					},
				},
			},
		},
		{
			name: "Can't index credit cards, status code: Internal",
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &creditCardsVaultMock{
					IndexFn: func(ctx context.Context, userID string) ([]models.CreditCard, error) {
						return nil, fmt.Errorf("can't index")
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, closer :=
				cardServiceClient(context.Background(), tt.serv.sessProvider, tt.serv.vault)
			defer closer()

			resp, err := client.IndexCreditCards(context.Background(), &emptypb.Empty{})
			if err != nil {
				if e, ok := status.FromError(err); ok {
					assert.EqualValues(t, tt.want.code, e.Code(),
						"Expected status code: %d, got %d", tt.want.code, e.Code())
					return
				} else {
					t.Fatalf("failed to parse: %v", err)
				}
			}

			names := make([][]byte, len(resp.Names))
			for i, n := range resp.Names {
				names[i], err = enc.Decrypt(n)
				require.NoError(t, err)
			}

			assert.EqualValues(t, tt.want.data.Names, names)
		})
	}
}

func TestCreditCardsService_DeleteCreditCard(t *testing.T) {
	// Prepare encrypter.
	key := "qlpdne07d7c2ut77qth9792ct7ah16oa"
	enc, err := testDataEncrypter(key)
	require.NoError(t, err)

	type services struct {
		sessProvider sessionProvider
		vault        creditCardsVault
	}
	type want struct {
		code codes.Code
	}
	tests := []struct {
		want       want
		serv       services
		recordName string
		name       string
	}{
		{
			name:       "Session not found, status code: Internal",
			recordName: "card",
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{},
				vault:        &creditCardsVaultMock{},
			},
		},
		{
			name:       "Corrupted session encrypter, status code: Internal",
			recordName: "card",
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(""))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &creditCardsVaultMock{},
			},
		},
		{
			name:       "Delete password, status code: Ok",
			recordName: "card",
			want: want{
				code: codes.OK,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &creditCardsVaultMock{
					DeleteFn: func(_ context.Context, _ models.ObjectMeta) error {
						return nil
					},
				},
			},
		},
		{
			name:       "Can't delete credit card, status code: Internal",
			recordName: "card",
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{
					SessionByIdFn: func(s string) (conn.Session, error) {
						session, err := conn.SessionFrom("1", []byte(key))
						if err != nil {
							return conn.Session{}, err
						}
						return session, nil
					},
				},
				vault: &creditCardsVaultMock{
					DeleteFn: func(_ context.Context, _ models.ObjectMeta) error {
						return fmt.Errorf("can't delete")
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, closer :=
				cardServiceClient(context.Background(), tt.serv.sessProvider, tt.serv.vault)
			defer closer()

			name, err := enc.Encrypt([]byte(tt.recordName))
			require.NoError(t, err)

			_, err = client.DeleteCreditCard(context.Background(), &creditcardpb.DeleteCreditCardRequest{
				Name: name,
			})
			if err != nil {
				if e, ok := status.FromError(err); ok {
					assert.EqualValues(t, tt.want.code, e.Code(),
						"Expected status code: %d, got %d", tt.want.code, e.Code())
					return
				} else {
					t.Fatalf("failed to parse: %v", err)
				}
			}
		})
	}
}

func cardServiceClient(
	ctx context.Context,
	sessProvider sessionProvider,
	vault creditCardsVault,
) (creditcardpb.CreditCardsVaultClient, func()) {
	buffer := 1024 * 1024
	lis := bufconn.Listen(buffer)

	baseServer := grpc.NewServer()
	RegisterCreditCardsVaultService(
		baseServer,
		sessProvider,
		vault,
	)
	go func() {
		if err := baseServer.Serve(lis); err != nil {
			log.Printf("error serving server: %v", err)
		}
	}()

	conn, err := grpc.DialContext(ctx, "",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("error connecting to server: %v", err)
	}

	closer := func() {
		err := lis.Close()
		if err != nil {
			log.Printf("error closing listener: %v", err)
		}
		baseServer.Stop()
	}

	client := creditcardpb.NewCreditCardsVaultClient(conn)
	return client, closer
}
