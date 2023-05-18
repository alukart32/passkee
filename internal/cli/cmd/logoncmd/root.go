package logoncmd

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"time"

	"github.com/alukart32/yandex/practicum/passkee/internal/cli/session"
	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/conn"
	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/authpb"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type dataEncrypter interface {
	Encrypt(plaintext []byte) ([]byte, error)
	EncryptBlock(plaintext []byte, blockNo uint64) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	DecryptBlock(ciphertext []byte, blockNo uint64) ([]byte, error)
}

type sessionHandler interface {
	Handshake(conn.Info) (conn.Session, error)
	Terminate() error
	AuthContext(context.Context) context.Context
	RemoteAddr() string
}

var (
	sessHandler sessionHandler
	encrypter   dataEncrypter
)

var root = &cobra.Command{
	Use:     "logon",
	Example: "logon -a server_address -u username -p password",
	Short:   "Log on to the server",
}

var (
	remoteAddr string
	username   string
	password   string
)

func Cmd() *cobra.Command {
	root.PreRunE = func(cmd *cobra.Command, args []string) error {
		// Create a new session handler.
		sessHandler = session.GrpcHandler()

		clientSession, err := sessHandler.Handshake(conn.Info{
			RemoteAddr: remoteAddr,
		})
		if err != nil {
			return err
		}
		encrypter, err = clientSession.DataEncrypter()
		if err != nil {
			return fmt.Errorf("can't prepare data encrypter: %v", err)
		}

		return nil
	}
	root.PostRunE = func(cmd *cobra.Command, args []string) error {
		return sessHandler.Terminate()
	}
	root.RunE = logon

	root.Flags().StringVarP(&remoteAddr, "addr", "a", "", "vault remote address")
	root.MarkFlagRequired("addr")
	root.Flags().StringVarP(&username, "username", "u", "", "username")
	root.Flags().StringVarP(&password, "password", "p", "", "password")
	root.MarkFlagsRequiredTogether("username", "password")

	return root
}

func logon(cmd *cobra.Command, args []string) error {
	hash := sha256.New()
	hash.Write([]byte(password))
	passwordHash := hash.Sum(nil)

	_username, err := encrypter.Encrypt([]byte(username))
	if err != nil {
		return fmt.Errorf("can't encrypt username: %v", err)
	}

	_password, err := encrypter.Encrypt(passwordHash)
	if err != nil {
		return fmt.Errorf("can't encrypt password: %v", err)
	}

	// Prepare gRPC auth client.
	conn, err := grpc.Dial(
		remoteAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()

	client := authpb.NewAuthClient(conn)

	logonCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, err = client.LogOn(sessHandler.AuthContext(logonCtx), &authpb.LogOnRequest{
		Username: _username,
		Password: _password,
	})

	if err != nil {
		if e, ok := status.FromError(err); ok {
			switch e.Code() {
			case codes.DeadlineExceeded:
				fmt.Println(e.Message())
			case codes.Internal:
				fmt.Printf("can't log on: %v", err)
			default:
				fmt.Println(e.Code(), e.Message())
			}
		} else {
			fmt.Printf("can't parse %v", err)
		}
	}
	return nil
}
