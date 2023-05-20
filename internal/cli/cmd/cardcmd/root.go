package cardcmd

import (
	"context"
	"fmt"
	"log"

	"github.com/alukart32/yandex/practicum/passkee/internal/cli/session"
	"github.com/alukart32/yandex/practicum/passkee/internal/pkg/conn"
	"github.com/spf13/cobra"
)

// dataEncrypter defines the session message encryptor.
type dataEncrypter interface {
	Encrypt(plaintext []byte) ([]byte, error)
	EncryptBlock(plaintext []byte, blockNo uint64) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	DecryptBlock(ciphertext []byte, blockNo uint64) ([]byte, error)
}

// sessionHandler defines the handler of the session with the server.
type sessionHandler interface {
	Handshake(conn.Info) (conn.Session, error)
	Terminate() error
	AuthContext(context.Context) context.Context
	RemoteAddr() string
}

var (
	sessHandler sessionHandler
	encrypter   dataEncrypter

	// root is the parent bin command.
	root = &cobra.Command{
		Use: "card [options]",
	}
)

// Cmd returns a new instance of the card command.
//
// The card command is executed in the following order:
//
//  1. entering authentication data
//  2. creating a new connection session with the server
//  3. executing a subcommand: add, get, delete, list, update
//  4. session termination.
func Cmd(
	connInfoProvider func() (conn.Info, error),
) *cobra.Command {
	root.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		// Read user input.
		connInfo, err := connInfoProvider()
		if err != nil {
			fmt.Println(err)
			return
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
			log.Fatalf("can't prepare data encrypter: %v", err)
		}
	}
	root.PersistentPostRun = func(cmd *cobra.Command, args []string) {
		if err := sessHandler.Terminate(); err != nil {
			log.Fatal(err)
		}
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
