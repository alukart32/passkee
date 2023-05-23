package cardcmd

import (
	"context"
	"fmt"

	"github.com/alukart32/yandex/practicum/passkee/internal/cli/session"
	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/conn"
	"github.com/spf13/cobra"
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
	Use: "card [options]",
}

func Cmd(
	connInfoProvider func() (conn.Info, error),
) *cobra.Command {
	root.PreRunE = func(cmd *cobra.Command, args []string) error {
		// Read user input.
		connInfo, err := connInfoProvider()
		if err != nil {
			return err
		}
		// Create a new session handler.
		sessHandler = session.GrpcHandler()

		// Try to handshake.
		clientSession, err := sessHandler.Handshake(connInfo)
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

	root.AddCommand(
		addCmd(),
		getCmd(),
		deleteCmd(),
		indexCmd(),
		updateCmd(),
	)

	return root
}
