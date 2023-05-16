package cardcmd

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/creditcardpb"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func indexCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "list",
		Short: "list all credit card records name",
	}
	cmd.RunE = indexE
	return &cmd
}

func indexE(cmd *cobra.Command, args []string) error {
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
	indexCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := client.IndexCreditCards(sessHandler.AuthContext(indexCtx), &emptypb.Empty{})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			switch e.Code() {
			case codes.DeadlineExceeded:
				fmt.Println(e.Message())
			case codes.Internal:
				fmt.Printf("can't index password records: %v", err)
			default:
				fmt.Println(e.Code(), e.Message())
			}
		} else {
			fmt.Printf("can't parse %v", err)
		}
	}

	var sb strings.Builder
	for i, v := range resp.Cards {
		name, err := encrypter.Decrypt([]byte(v.Name))
		if err != nil {
			return fmt.Errorf("can't read response data: %v", err)
		}

		fmt.Fprintf(&sb, "%d. %v\n", i, string(name))
	}
	fmt.Printf("Records\n%v", sb.String())
	return nil
}
