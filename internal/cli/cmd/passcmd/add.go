package passcmd

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"time"

	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/passwordpb"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func addCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:     "add value",
		Short:   "put new credential in vault",
		Example: `add -n online_store username:password`,
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
var credsReg = regexp.MustCompile(`^([0-9A-Za-z@#$%*_^\\]{1,15}):([0-9A-Za-z@#$%*_^\\]{1,15})$`)

func addE(cmd *cobra.Command, args []string) error {
	data := args[0]

	if !credsReg.MatchString(data) {
		return fmt.Errorf("invalid format, must be username:password")
	}

	recordName, err := encrypter.Encrypt([]byte(name))
	if err != nil {
		return fmt.Errorf("can't prepare data for sending: %v", err)
	}

	recordData, err := encrypter.Encrypt([]byte(data))
	if err != nil {
		return fmt.Errorf("can't prepare data for sending: %v", err)
	}

	var recordNotes []byte
	if len(notes) != 0 {
		recordNotes, err = encrypter.Encrypt([]byte(notes))
		if err != nil {
			return fmt.Errorf("can't prepare data for sending: %v", err)
		}
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

	client := passwordpb.NewPasswordsVaultClient(conn)
	addCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.AddPassword(sessHandler.AuthContext(addCtx),
		&passwordpb.AddPasswordRequest{
			Password: &passwordpb.Password{
				Name:  recordName,
				Data:  recordData,
				Notes: recordNotes,
			},
		})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			err = fmt.Errorf("%v", e.Message())
		} else {
			err = fmt.Errorf("can't parse %v", err)
		}
		return err
	}

	fmt.Println("record added")
	return nil
}
