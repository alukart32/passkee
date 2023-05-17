package cardcmd

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/creditcardpb"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func deleteCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:     "delete",
		Short:   "delete credit card from vault",
		Example: `delete -n record_name`,
	}
	cmd.RunE = delete

	cmd.Flags().StringVarP(&name, "name", "n", "", "Record name")
	cmd.MarkFlagRequired("name")

	return &cmd
}

func delete(cmd *cobra.Command, args []string) error {
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

	client := creditcardpb.NewCreditCardsVaultClient(conn)
	deleteCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.DeleteCreditCard(sessHandler.AuthContext(deleteCtx), &creditcardpb.DeleteCreditCardRequest{
		Name: string(recordName),
	})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			err = fmt.Errorf("can't delete credit card: %v", e.Message())
		} else {
			err = fmt.Errorf("can't parse %v", err)
		}
		return err
	}
	fmt.Println("record deleted")
	return nil
}
