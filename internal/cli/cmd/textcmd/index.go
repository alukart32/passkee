package textcmd

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/blobpb"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func indexCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "list",
		Short: "List all text records names",
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

	client := blobpb.NewBlobVaultClient(conn)
	indexCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	resp, err := client.IndexObjects(indexCtx, &blobpb.IndexObjectsRequest{
		Typ: blobpb.ObjectType_OBJECT_BIN,
	})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			err = fmt.Errorf("can't index text records: %v", e.Message())
		} else {
			err = fmt.Errorf("can't parse %v", err)
		}
		return err
	}

	var sb strings.Builder
	for i, v := range resp.Objects {
		name, err := encrypter.Decrypt([]byte(v.Name))
		if err != nil {
			return fmt.Errorf("can't read response data: %v", err)
		}

		fmt.Fprintf(&sb, "%d. %v\n", i, string(name))
	}
	fmt.Printf("Records\n%v", sb.String())
	return nil
}
