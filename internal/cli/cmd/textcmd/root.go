package textcmd

import (
	"context"
	"log"

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
	Use: "text [options]",
}

func Cmd(
	connInfoProvider func() (conn.Info, error),
) *cobra.Command {
	root.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		// Read user input.
		connInfo, err := connInfoProvider()
		if err != nil {
			log.Fatal(err)
		}

		// Create a new session handler.
		sessHandler = session.GrpcHandler()
		// Try to handshake.
		clientSession, err := sessHandler.Handshake(connInfo)
		if err != nil {
			log.Fatal(err)
		}
		encrypter, err = clientSession.DataEncrypter()
		if err != nil {
			log.Fatal(err)
		}
	}
	root.PersistentPostRun = func(cmd *cobra.Command, args []string) {
		if err := sessHandler.Terminate(); err != nil {
			log.Fatal(err)
		}
	}

	root.AddCommand(
		addCmd(),
		deleteCmd(),
		getCmd(),
		indexCmd(),
		updateCmd(),
	)

	return root
}
