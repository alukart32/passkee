package passcmd

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/passwordpb"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func indexCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "list",
		Short: "list all credential records names",
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

	client := passwordpb.NewPasswordsVaultClient(conn)
	indexCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := client.IndexPasswords(
		sessHandler.AuthContext(indexCtx),
		&emptypb.Empty{})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			err = fmt.Errorf("%v", e.Message())
		} else {
			err = fmt.Errorf("can't parse %v", err)
		}
		return err
	}

	if len(resp.Names) == 0 {
		fmt.Println("No records")
		return nil
	}

	var sb strings.Builder
	for i, v := range resp.Names {
		name, err := encrypter.Decrypt([]byte(v))
		if err != nil {
			return fmt.Errorf("can't read response data: %v", err)
		}
		fmt.Fprintf(&sb, "  %d. %v\n", i+1, string(name))
	}
	fmt.Printf("Records\n%v", sb.String())
	return nil
}
