package v1

import (
	"context"
	"fmt"
	"log"
	"net"
	"testing"

	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/aesgcm"
	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/conn"
	"github.com/alukart32/yandex/practicum/passkee/internal/vault/models"
	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/authpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type sessionProviderMock struct {
	SessionByIdFn func(string) (conn.Session, error)
}

func (m *sessionProviderMock) SessionById(id string) (conn.Session, error) {
	if m != nil && m.SessionByIdFn != nil {
		return m.SessionByIdFn(id)
	}
	return conn.Session{}, fmt.Errorf("no such session")
}

type userSaverMock struct {
	SaveFn func(context.Context, models.User) error
}

func (m *userSaverMock) Save(ctx context.Context, user models.User) error {
	if m != nil && m.SaveFn != nil {
		return m.SaveFn(ctx, user)
	}
	return fmt.Errorf("can't save a new user")
}

func TestAuthService_LogOn(t *testing.T) {
	// Prepare encrypter.
	key := "Zuy4B2CiHyYKtaoCV9clnuMdi7eV3cOi"
	enc, err := testDataEncrypter(key)
	require.NoError(t, err)

	// Prepare user data.
	username, err := enc.Encrypt([]byte("user"))
	require.NoError(t, err)
	password, err := enc.Encrypt([]byte("user"))
	require.NoError(t, err)

	type services struct {
		sessProvider sessionProvider
		userSaver    userSaver
	}
	type want struct {
		code codes.Code
	}
	tests := []struct {
		want want
		serv services
		req  *authpb.LogOnRequest
		name string
	}{
		{
			name: "Session not found, status code: Internal",
			req: &authpb.LogOnRequest{
				Username: username,
				Password: password,
			},
			want: want{
				code: codes.Internal,
			},
			serv: services{
				sessProvider: &sessionProviderMock{},
				userSaver:    &userSaverMock{},
			},
		},
		{
			name: "Corrupted session encrypter, status code: Internal",
			req: &authpb.LogOnRequest{
				Username: username,
				Password: password,
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
				userSaver: &userSaverMock{},
			},
		},
		{
			name: "Valid user, status code: Ok",
			req: &authpb.LogOnRequest{
				Username: username,
				Password: password,
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
				userSaver: &userSaverMock{
					SaveFn: func(_ context.Context, u models.User) error {
						return nil
					},
				},
			},
		},
		{
			name: "Invalid username encryption, status code: Internal",
			req: &authpb.LogOnRequest{
				Username: []byte("user"),
				Password: password,
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
				userSaver: &userSaverMock{},
			},
		},
		{
			name: "Invalid password encryption, status code: Internal",
			req: &authpb.LogOnRequest{
				Username: username,
				Password: []byte("user"),
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
				userSaver: &userSaverMock{},
			},
		},
		{
			name: "Can't save valid user, status code: Internal",
			req: &authpb.LogOnRequest{
				Username: username,
				Password: password,
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
				userSaver: &userSaverMock{
					SaveFn: func(_ context.Context, u models.User) error {
						return fmt.Errorf("can't save")
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, closer :=
				authServiceClient(context.Background(), tt.serv.sessProvider, tt.serv.userSaver)
			defer closer()

			_, err := client.LogOn(context.Background(), tt.req)
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

func authServiceClient(
	ctx context.Context,
	sessProvider sessionProvider,
	userSaver userSaver,
) (authpb.AuthClient, func()) {
	buffer := 1024 * 1024
	lis := bufconn.Listen(buffer)

	baseServer := grpc.NewServer()
	RegisterAuthService(
		baseServer,
		sessProvider,
		userSaver,
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

	client := authpb.NewAuthClient(conn)
	return client, closer
}

func testDataEncrypter(key string) (conn.DataEncrypter, error) {
	gcmKey, err := aesgcm.Encrypter([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("can't create a new encryption key: %v", err)
	}
	return gcmKey, nil
}
