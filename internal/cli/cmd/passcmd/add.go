package passcmd

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/passwordspb"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func addCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:     "add [--n name]([-notes]) value",
		Short:   "Put new credential in vault",
		Example: `add --n online_store login:password`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.RunE = addE

	cmd.Flags().StringVarP(&name, "name", "n", "", "Name of the new record")
	cmd.MarkFlagRequired("name")
	cmd.Flags().StringVarP(&notes, "notes", "", "", "Extra notes")

	return &cmd
}

var name, notes string

func addE(cmd *cobra.Command, args []string) error {
	data := args[0]

	creds := strings.Split(data, ":")
	if len(creds) != 2 {
		return fmt.Errorf("invalid creds format, must be user:password")
	}

	encName, err := encrypter.Encrypt([]byte(name))
	if err != nil {
		return fmt.Errorf("unexpected encryption err: %v", err)
	}

	encData, err := encrypter.Encrypt([]byte(data))
	if err != nil {
		return fmt.Errorf("unexpected encryption err: %v", err)
	}

	var encNotes string
	if len(notes) != 0 {
		tmp, err := encrypter.Encrypt([]byte(notes))
		if err != nil {
			return fmt.Errorf("unexpected encryption err: %v", err)
		}

		encNotes = string(tmp)
	}

	// Prepare gRPC auth client.
	conn, err := grpc.Dial(
		sessHandler.RemoteAddr(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()

	client := passwordspb.NewPasswordsVaultClient(conn)

	// Prepare payload.
	in := passwordspb.AddPasswordRequest{
		Password: &passwordspb.Password{
			Name:  string(encName),
			Data:  string(encData),
			Notes: &encNotes,
		},
	}

	addCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.AddPassword(sessHandler.AuthContext(addCtx), &in)
	if err != nil {
		// TODO: process error.
	}

	return nil
}
