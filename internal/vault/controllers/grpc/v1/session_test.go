package v1

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"testing"

	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/conn"
	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/authpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

type connHandlerMock struct {
	InitSessionFn      func() (conn.Session, error)
	TerminateSessionFn func(id string)
}

func (m *connHandlerMock) InitSession() (conn.Session, error) {
	if m != nil && m.InitSessionFn != nil {
		return m.InitSessionFn()
	}
	return conn.Session{}, fmt.Errorf("can't init a new session")
}

func (m *connHandlerMock) TerminateSession(id string) {
	if m != nil && m.TerminateSessionFn != nil {
		m.TerminateSessionFn(id)
	}
}

func TestSessionService_Handshake(t *testing.T) {
	type services struct {
		chandler connHandler
	}
	type want struct {
		data *authpb.ServerSession
		code codes.Code
	}
	tests := []struct {
		want want
		serv services
		name string
	}{
		{
			name: "Hadshake, status code: Ok",
			want: want{
				data: &authpb.ServerSession{
					Id: "1",
				},
				code: codes.OK,
			},
			serv: services{
				chandler: &connHandlerMock{
					InitSessionFn: func() (conn.Session, error) {
						session, err := conn.NewSession()
						if err != nil {
							return conn.Session{}, err
						}
						session.Id = "1"
						return session, nil
					},
				},
			},
		},
		{
			name: "Hadshake, status code: Internal",
			want: want{
				data: &authpb.ServerSession{
					Id: "1",
				},
				code: codes.Internal,
			},
			serv: services{
				chandler: &connHandlerMock{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, closer :=
				sessionServiceClient(context.Background(), tt.serv.chandler)
			defer closer()

			resp, err := client.Handshake(context.Background(), &emptypb.Empty{})
			if err != nil {
				if e, ok := status.FromError(err); ok {
					assert.EqualValues(t, tt.want.code, e.Code(),
						"Expected status code: %d, got %d", tt.want.code, e.Code())
					return
				} else {
					t.Fatalf("failed to parse: %v", err)
				}
			}
			assert.NotEmpty(t, resp.Id)
			id, err := base64.StdEncoding.DecodeString(resp.Id)
			require.NoError(t, err)
			assert.EqualValues(t, tt.want.data.Id, id, "Expected id: %s, got %s", tt.want.data.Id, id)
		})
	}
}

func TestSessionService_TerminateSession(t *testing.T) {
	id := base64.StdEncoding.EncodeToString([]byte("1"))

	type services struct {
		chandler connHandler
	}
	type want struct {
		code codes.Code
	}
	tests := []struct {
		req  *authpb.TerminateRequest
		want want
		serv services
		name string
	}{
		{
			name: "Terminate session, status code: Ok",
			want: want{
				code: codes.OK,
			},
			req: &authpb.TerminateRequest{
				Id: id,
			},
			serv: services{
				chandler: &connHandlerMock{
					TerminateSessionFn: func(id string) {
						if id != "1" {
							panic(fmt.Errorf("no such session"))
						}
					},
				},
			},
		},
		{
			name: "Terminate session - corrupted id, status code: Internal",
			want: want{
				code: codes.Internal,
			},
			req: &authpb.TerminateRequest{
				Id: "_",
			},
			serv: services{
				chandler: &connHandlerMock{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, closer :=
				sessionServiceClient(context.Background(), tt.serv.chandler)
			defer closer()

			_, err := client.Terminate(context.Background(), tt.req)
			if err != nil {
				if e, ok := status.FromError(err); ok {
					assert.EqualValues(t, tt.want.code, e.Code(),
						"Expected status code: %d, got %d", tt.want.code, e.Code())
					return
				} else {
					t.Fatalf("failed to parse: %v", err)
				}
			}
			require.NoError(t, err)
		})
	}
}

func sessionServiceClient(
	ctx context.Context,
	connH connHandler,
) (authpb.SessionClient, func()) {
	buffer := 1024 * 1024
	lis := bufconn.Listen(buffer)

	baseServer := grpc.NewServer()
	RegisterSessionService(baseServer, connH)
	go func() {
		if err := baseServer.Serve(lis); err != nil {
			log.Printf("error serving server: %v", err)
		}
	}()

	conn, err := grpc.DialContext(
		ctx, "",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
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

	client := authpb.NewSessionClient(conn)
	return client, closer
}
