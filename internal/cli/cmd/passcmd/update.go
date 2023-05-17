package passcmd

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/passwordpb"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func updateCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "update value",
		Short: "update credential record",
		Example: `update -n record_name -r new_record_name
update -n record_name username:password
update -n record_name --notes "new record notes"`,
	}

	cmd.RunE = updateE

	cmd.Flags().StringVarP(&name, "name", "n", "", "Record name")
	cmd.MarkFlagRequired("name")
	cmd.Flags().StringVarP(&notes, "notes", "", "", "Notes of the record")
	cmd.Flags().StringVarP(&newRecordName, "record_name", "r", "", "Record name to update")
	return &cmd
}

var newRecordName string

func updateE(cmd *cobra.Command, args []string) error {
	recordName, err := encrypter.Encrypt([]byte(name))
	if err != nil {
		return fmt.Errorf("can't prepare data for sending: %v", err)
	}

	var newName string
	if len(newRecordName) != 0 {
		b, err := encrypter.Encrypt([]byte(newRecordName))
		if err != nil {
			return fmt.Errorf("can't prepare data for sending: %v", err)
		}
		newName = string(b)
	}

	data := args[0]
	var newData string
	if len(data) > 0 {
		if !credsReg.MatchString(data) {
			return fmt.Errorf("invalid format, must be username:password")
		}

		b, err := encrypter.Encrypt([]byte(data))
		if err != nil {
			return fmt.Errorf("can't prepare data for sending: %v", err)
		}
		newData = string(b)
	}

	var newNotes string
	if len(notes) != 0 {
		b, err := encrypter.Encrypt([]byte(notes))
		if err != nil {
			return fmt.Errorf("can't prepare data for sending: %v", err)
		}
		newNotes = string(b)
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
	updCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.ResetPassword(sessHandler.AuthContext(updCtx), &passwordpb.ResetPasswordRequest{
		Name: string(recordName),
		Password: &passwordpb.ResetPasswordRequest_ResetPassword{
			Name:  &newName,
			Data:  &newData,
			Notes: &newNotes,
		},
	})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			err = fmt.Errorf("can't update password: %v", e.Message())
		} else {
			err = fmt.Errorf("can't parse %v", err)
		}
		return err
	}
	fmt.Println("record updated")
	return nil
}
