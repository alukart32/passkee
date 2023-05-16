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

func deleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "delete",
		Short:   "delete credential from vault",
		Example: "delete -n record_name",
	}
	cmd.RunE = deleteE

	cmd.Flags().StringVarP(&name, "name", "n", "", "Record name")
	cmd.MarkFlagRequired("name")

	return cmd
}

func deleteE(cmd *cobra.Command, args []string) error {
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
	deleteCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.DeletePassword(sessHandler.AuthContext(deleteCtx),
		&passwordpb.DeletePasswordRequest{
			Name: string(recordName),
		})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			switch e.Code() {
			case codes.DeadlineExceeded:
				fmt.Println(e.Message())
			case codes.Internal:
				fmt.Printf("can't delete password record: %v", err)
			default:
				fmt.Println(e.Code(), e.Message())
			}
		} else {
			fmt.Printf("can't parse %v", err)
		}
	}
	fmt.Println("record deleted")
	return nil
}
