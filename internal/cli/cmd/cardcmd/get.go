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

func getCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:     "get",
		Short:   "get credit card from vault",
		Example: `get -n record_name`,
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

	client := creditcardpb.NewCreditCardsVaultClient(conn)
	getCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := client.GetCreditCard(sessHandler.AuthContext(getCtx), &creditcardpb.GetCreditCardRequest{
		Name: recordName,
	})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			err = fmt.Errorf("%v", e.Message())
		} else {
			err = fmt.Errorf("can't parse %v", err)
		}
		return err
	}

	recordData, err := encrypter.Decrypt([]byte(resp.Data))
	if err != nil {
		return fmt.Errorf("can't read response data: %v", err)
	}

	var recordNotes string
	if len(resp.Notes) != 0 {
		b, err := encrypter.Decrypt(resp.Notes)
		if err != nil {
			return fmt.Errorf("can't read response data: %v", err)
		}
		recordNotes = string(b)
	}

	fmt.Printf("Record\n  name : %v\n  data : %v\n  notes: %v",
		name, string(recordData), recordNotes)
	return nil
}
