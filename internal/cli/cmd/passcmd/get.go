package passcmd

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/passwordpb"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func getCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:     "get",
		Short:   "get credential from vault",
		Example: "get -n record_name",
	}
	cmd.RunE = getE

	cmd.Flags().StringVarP(&name, "name", "n", "", "Record name")
	cmd.MarkFlagRequired("name")

	return &cmd
}

func getE(cmd *cobra.Command, args []string) error {
	recordName, err := encrypter.Encrypt([]byte(name))
	if err != nil {
		return fmt.Errorf("can't prepare data for sending: %v", err)
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
	getCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := client.GetPassword(sessHandler.AuthContext(getCtx),
		&passwordpb.GetPasswordRequest{
			Name: string(recordName),
		})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			switch e.Code() {
			case codes.DeadlineExceeded:
				fmt.Println(e.Message())
			case codes.Internal | codes.Unknown:
				fmt.Printf("can't get password record: %v", err)
			default:
				fmt.Println(e.Code(), e.Message())
			}
		} else {
			fmt.Printf("can't parse %v", err)
		}
	}

	recordData, err := encrypter.Decrypt([]byte(resp.Data))
	if err != nil {
		return fmt.Errorf("can't read response data: %v", err)
	}

	recordNotes, err := encrypter.Decrypt([]byte(*resp.Notes))
	if err != nil {
		return fmt.Errorf("can't read response data: %v", err)
	}

	fmt.Printf("\nName: %v\nEntry: %v\nNotes: %v",
		name, string(recordData), string(recordNotes))
	return nil
}
