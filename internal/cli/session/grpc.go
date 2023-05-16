// The session package defines the session handlers of connections with the server.
package session

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/conn"
	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/authpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// grpcHandler represents a gRPC connection handler.
type grpcHandler struct {
	connInfo conn.Info
	session  conn.Session
}

// GrpcHandler returns a new grpcHandler.
func GrpcHandler() *grpcHandler {
	return &grpcHandler{}
}

// Handshake creates a new client-server session. Upon request, the server returns
// the message encryption key.
func (h *grpcHandler) Handshake(in conn.Info) (conn.Session, error) {
	h.connInfo = in

	// Prepare gRPC client.
	cc, err := grpc.Dial(
		in.RemoteAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer cc.Close()

	// Set auth credentials in the basic format.
	client := authpb.NewSessionClient(cc)

	handshakeCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	resp, err := client.Handshake(
		handshakeCtx,
		&emptypb.Empty{},
	)
	if err != nil {
		if e, ok := status.FromError(err); ok {
			err = fmt.Errorf("handshake failed: %v", e.Message())
		} else {
			err = fmt.Errorf("can't parse %v", err)
		}
		return conn.Session{}, err
	}

	// Prepare session context.
	sessionKey, err := base64.StdEncoding.DecodeString(resp.Key)
	if err != nil {
		return conn.Session{}, fmt.Errorf("can't parse session key: %v", err)
	}

	return conn.SessionFrom(resp.Id, sessionKey)
}

// Terminate ends the established session with the server.
func (h *grpcHandler) Terminate() error {
	// Prepare gRPC client.
	cc, err := grpc.Dial(
		h.connInfo.RemoteAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer cc.Close()

	// Set auth credentials in the basic format.
	client := authpb.NewSessionClient(cc)

	terminateCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err = client.Terminate(
		terminateCtx,
		&authpb.TerminateRequest{
			Id: h.session.Id,
		},
	)
	if err != nil {
		if e, ok := status.FromError(err); ok {
			err = fmt.Errorf("can't terminate session: %v", e.Message())
		} else {
			err = fmt.Errorf("can't parse %v", err)
		}
		return err
	}
	return nil
}

// AuthContext creates a new context for authorization.
func (h *grpcHandler) AuthContext(ctx context.Context) context.Context {
	md := metadata.New(map[string]string{
		"authorization": "basic " + string(h.connInfo.Creds),
	})
	md.Set("session_id", h.session.Id)

	return metadata.NewOutgoingContext(ctx, md)
}

// RemoteAddr returns server remote address.
func (h *grpcHandler) RemoteAddr() string {
	return h.connInfo.RemoteAddr
}
