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
	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/passwordpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

type passwordsVaultMock struct {
	SaveFn   func(context.Context, models.Password) error
	GetFn    func(context.Context, models.ObjectMeta) (models.Password, error)
	IndexFn  func(ctx context.Context, userID string) ([]models.Password, error)
	ResetFn  func(ctx context.Context, meta models.ObjectMeta, data models.Password) error
	DeleteFn func(ctx context.Context, meta models.ObjectMeta) error
}

func (m *passwordsVaultMock) Save(ctx context.Context, p models.Password) error {
	if m != nil && m.SaveFn != nil {
		return m.SaveFn(ctx, p)
	}
	return fmt.Errorf("can't save a new password pair")
}

func (m *passwordsVaultMock) Get(ctx context.Context, meta models.ObjectMeta) (models.Password, error) {
	if m != nil && m.GetFn != nil {
		return m.GetFn(ctx, meta)
	}
	return models.Password{}, fmt.Errorf("can't get a password pair")
}

func (m *passwordsVaultMock) Index(ctx context.Context, userID string) ([]models.Password, error) {
	if m != nil && m.IndexFn != nil {
		return m.IndexFn(ctx, userID)
	}
	return []models.Password{}, fmt.Errorf("can't index password pairs")
}

func (m *passwordsVaultMock) Reset(ctx context.Context, meta models.ObjectMeta, data models.Password) error {
	if m != nil && m.ResetFn != nil {
		return m.ResetFn(ctx, meta, data)
	}
	return fmt.Errorf("can't reset password pair")
}

func (m *passwordsVaultMock) Delete(ctx context.Context, meta models.ObjectMeta) error {
	if m != nil && m.DeleteFn != nil {
		return m.DeleteFn(ctx, meta)
	}
	return fmt.Errorf("can't delete password pair")
}

func TestPasswordsService_AddPassword(t *testing.T) {
	// Prepare encrypter.
	key := "Zuy4B2CiHyYKtaoCV9clnuMdi7eV3cOi"
	enc, err := testDataEncrypter(key)
	require.NoError(t, err)

	type password struct {
		name  string
		data  string
		notes string
	}
	type services struct {
		sessProvider sessionProvider
		vault        passwordsVault
	}
	type want struct {
		code codes.Code
	}
	tests := []struct {
		want want
		serv services
		req  password
		name string
	}{
		{
			name: "Session not found, status code: Internal",
			req: password{
				name:  "pass",
				data:  "user:pass",
				notes: "notes",
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{},
				vault:        &passwordsVaultMock{},
			},
		},
		{
			name: "Corrupted session encrypter, status code: Internal",
			req: password{
				name:  "pass",
				data:  "user:pass",
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
				vault: &passwordsVaultMock{},
			},
		},
		{
			name: "Valid password, status code: Ok",
			req: password{
				name:  "pass",
				data:  "user:pass",
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
				vault: &passwordsVaultMock{
					SaveFn: func(_ context.Context, _ models.Password) error {
						return nil
					},
				},
			},
		},
		{
			name: "Invalid format, status code: InvalidArgument",
			req: password{
				name:  "pass",
				data:  "user/pass",
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
				vault: &passwordsVaultMock{},
			},
		},
		{
			name: "Not unique username, status code: InvalidArgument",
			req: password{
				name:  "pass",
				data:  "user:pass",
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
				vault: &passwordsVaultMock{
					SaveFn: func(_ context.Context, _ models.Password) error {
						return storage.ErrNameUniqueViolation
					},
				},
			},
		},
		{
			name: "Can't save valid password, status code: Internal",
			req: password{
				name:  "pass",
				data:  "user:pass",
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
				vault: &passwordsVaultMock{
					SaveFn: func(_ context.Context, _ models.Password) error {
						return fmt.Errorf("can't save")
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, closer :=
				passServiceClient(context.Background(), tt.serv.sessProvider, tt.serv.vault)
			defer closer()

			name, err := enc.Encrypt([]byte(tt.req.name))
			require.NoError(t, err)
			data, err := enc.Encrypt([]byte(tt.req.data))
			require.NoError(t, err)
			notes, err := enc.Encrypt([]byte(tt.req.notes))
			require.NoError(t, err)

			_, err = client.AddPassword(context.Background(), &passwordpb.AddPasswordRequest{
				Password: &passwordpb.Password{
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

func TestPasswordsService_ResetPassword(t *testing.T) {
	// Prepare encrypter.
	key := "Zuy4B2CiHyYKtaoCV9clnuMdi7eV3cOi"
	enc, err := testDataEncrypter(key)
	require.NoError(t, err)

	type password struct {
		name     string
		newName  string
		newData  string
		newNotes string
	}
	type services struct {
		sessProvider sessionProvider
		vault        passwordsVault
	}
	type want struct {
		code codes.Code
	}
	tests := []struct {
		want want
		serv services
		req  password
		name string
	}{
		{
			name: "Session not found, status code: Internal",
			req: password{
				name:     "pass",
				newName:  "pass2",
				newData:  "user:pass",
				newNotes: "notes",
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{},
				vault:        &passwordsVaultMock{},
			},
		},
		{
			name: "Corrupted session encrypter, status code: Internal",
			req: password{
				name:     "pass",
				newName:  "pass2",
				newData:  "user:pass",
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
				vault: &passwordsVaultMock{},
			},
		},
		{
			name: "Valid password, status code: Ok",
			req: password{
				name:     "pass",
				newName:  "pass2",
				newData:  "user:pass",
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
				vault: &passwordsVaultMock{
					ResetFn: func(_ context.Context, _ models.ObjectMeta, _ models.Password) error {
						return nil
					},
				},
			},
		},
		{
			name: "Nothing to update, status code: InvalidArgument",
			req: password{
				name: "pass",
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
				vault: &passwordsVaultMock{
					ResetFn: func(_ context.Context, _ models.ObjectMeta, _ models.Password) error {
						return nil
					},
				},
			},
		},
		{
			name: "Invalid format, status code: InvalidArgument",
			req: password{
				name:     "pass",
				newName:  "pass2",
				newData:  "user/pass",
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
				vault: &passwordsVaultMock{},
			},
		},
		{
			name: "Can't reset valid password, status code: Internal",
			req: password{
				name:     "pass",
				newName:  "pass2",
				newData:  "user:pass",
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
				vault: &passwordsVaultMock{
					ResetFn: func(_ context.Context, _ models.ObjectMeta, _ models.Password) error {
						return fmt.Errorf("can't reset")
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, closer :=
				passServiceClient(context.Background(), tt.serv.sessProvider, tt.serv.vault)
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
			_, err = client.ResetPassword(context.Background(), &passwordpb.ResetPasswordRequest{
				Name: name,
				Password: &passwordpb.ResetPasswordRequest_ResetPassword{
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

func TestPasswordsService_GetPassword(t *testing.T) {
	// Prepare encrypter.
	key := "Zuy4B2CiHyYKtaoCV9clnuMdi7eV3cOi"
	enc, err := testDataEncrypter(key)
	require.NoError(t, err)

	// Prepare user data.
	type services struct {
		sessProvider sessionProvider
		vault        passwordsVault
	}
	type want struct {
		data *passwordpb.Password
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
			recordName: "pass",
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{},
				vault:        &passwordsVaultMock{},
			},
		},
		{
			name:       "Corrupted session encrypter, status code: Internal",
			recordName: "pass",
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
				vault: &passwordsVaultMock{},
			},
		},
		{
			name:       "Return password, status code: Ok",
			recordName: "pass",
			want: want{
				data: &passwordpb.Password{
					Name:  []byte("pass"),
					Data:  []byte("user:pass"),
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
				vault: &passwordsVaultMock{
					GetFn: func(_ context.Context, om models.ObjectMeta) (models.Password, error) {
						return models.Password{
							Meta: om,
							Data: []byte("user:pass"),
						}, nil
					},
				},
			},
		},
		{
			name:       "No such password, status code: Unknown",
			recordName: "pass2",
			want: want{
				data: &passwordpb.Password{
					Name:  []byte("pass"),
					Data:  []byte("user:pass"),
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
				vault: &passwordsVaultMock{
					GetFn: func(_ context.Context, om models.ObjectMeta) (models.Password, error) {
						return models.Password{}, nil
					},
				},
			},
		},
		{
			name:       "Can't get password pair, status code: Internal",
			recordName: "pass",
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
				vault: &passwordsVaultMock{
					SaveFn: func(_ context.Context, _ models.Password) error {
						return fmt.Errorf("can't get")
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, closer :=
				passServiceClient(context.Background(), tt.serv.sessProvider, tt.serv.vault)
			defer closer()

			name, err := enc.Encrypt([]byte(tt.recordName))
			require.NoError(t, err)

			resp, err := client.GetPassword(context.Background(), &passwordpb.GetPasswordRequest{
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

func TestPasswordsService_IndexPasswords(t *testing.T) {
	// Prepare encrypter.
	key := "Zuy4B2CiHyYKtaoCV9clnuMdi7eV3cOi"
	enc, err := testDataEncrypter(key)
	require.NoError(t, err)

	type services struct {
		sessProvider sessionProvider
		vault        passwordsVault
	}
	type want struct {
		data *passwordpb.IndexPasswordsResponse
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
				vault:        &passwordsVaultMock{},
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
				vault: &passwordsVaultMock{},
			},
		},
		{
			name: "Return passwords, status code: Ok",
			want: want{
				data: &passwordpb.IndexPasswordsResponse{
					Names: [][]byte{[]byte("p_1"), []byte("p_2"), []byte("p_3")},
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
				vault: &passwordsVaultMock{
					IndexFn: func(ctx context.Context, userID string) ([]models.Password, error) {
						records := []models.Password{
							{
								Meta: models.ObjectMeta{
									Name: []byte("p_1"),
								},
							},
							{
								Meta: models.ObjectMeta{
									Name: []byte("p_2"),
								},
							},
							{
								Meta: models.ObjectMeta{
									Name: []byte("p_3"),
								},
							},
						}
						return records, nil
					},
				},
			},
		},
		{
			name: "Can't index password pairs, status code: Internal",
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
				vault: &passwordsVaultMock{
					IndexFn: func(ctx context.Context, userID string) ([]models.Password, error) {
						return nil, fmt.Errorf("can't index")
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, closer :=
				passServiceClient(context.Background(), tt.serv.sessProvider, tt.serv.vault)
			defer closer()

			resp, err := client.IndexPasswords(context.Background(), &emptypb.Empty{})
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

func TestPasswordsService_DeletePassword(t *testing.T) {
	// Prepare encrypter.
	key := "Zuy4B2CiHyYKtaoCV9clnuMdi7eV3cOi"
	enc, err := testDataEncrypter(key)
	require.NoError(t, err)

	type services struct {
		sessProvider sessionProvider
		vault        passwordsVault
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
			recordName: "pass",
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{},
				vault:        &passwordsVaultMock{},
			},
		},
		{
			name:       "Corrupted session encrypter, status code: Internal",
			recordName: "pass",
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
				vault: &passwordsVaultMock{},
			},
		},
		{
			name:       "Delete password, status code: Ok",
			recordName: "pass",
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
				vault: &passwordsVaultMock{
					DeleteFn: func(_ context.Context, _ models.ObjectMeta) error {
						return nil
					},
				},
			},
		},
		{
			name:       "Can't delete password, status code: Internal",
			recordName: "pass",
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
				vault: &passwordsVaultMock{
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
				passServiceClient(context.Background(), tt.serv.sessProvider, tt.serv.vault)
			defer closer()

			name, err := enc.Encrypt([]byte(tt.recordName))
			require.NoError(t, err)

			_, err = client.DeletePassword(context.Background(), &passwordpb.DeletePasswordRequest{
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

func passServiceClient(
	ctx context.Context,
	sessProvider sessionProvider,
	vault passwordsVault,
) (passwordpb.PasswordsVaultClient, func()) {
	buffer := 1024 * 1024
	lis := bufconn.Listen(buffer)

	baseServer := grpc.NewServer()
	RegisterPasswordsVaultService(
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

	client := passwordpb.NewPasswordsVaultClient(conn)
	return client, closer
}
