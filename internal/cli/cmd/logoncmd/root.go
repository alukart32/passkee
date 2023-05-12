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
	"google.golang.org/grpc/credentials/insecure"
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
	Example: "logon -a server_address -u myname -p pass",
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
			Creds:      "",
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
	root.RunE = signup

	root.Flags().StringVarP(&remoteAddr, "addr", "a", "http://localhost:8080", "vault remote address")
	root.MarkFlagRequired("addr")
	root.Flags().StringVarP(&username, "username", "u", "", "username")
	root.Flags().StringVarP(&password, "password", "p", "", "password")
	root.MarkFlagsRequiredTogether("username", "password")

	return root
}

func signup(cmd *cobra.Command, args []string) error {
	hash := sha256.New()
	hash.Write([]byte(password))
	passwordHash := hash.Sum(nil)

	encUsername, err := encrypter.Encrypt([]byte(username))
	if err != nil {
		return fmt.Errorf("can't encrypt username: %v", err)
	}

	encPassword, err := encrypter.Encrypt(passwordHash)
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

	signUpCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, err = client.LogOn(signUpCtx, &authpb.LogOnRequest{
		Username: encUsername,
		Password: encPassword,
	})

	// TODO: check errors
	if err != nil {
		return fmt.Errorf("failed to start a new session: %v", err)
	}

	return nil
}
