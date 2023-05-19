package textcmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/blobpb"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func getCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:     "get",
		Short:   "get text from vault",
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

	client := blobpb.NewBlobVaultClient(conn)
	getCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.DownloadObject(
		sessHandler.AuthContext(getCtx),
		&blobpb.DownloadObjectRequest{
			Name: recordName,
			Typ:  blobpb.ObjectType_OBJECT_BIN,
		},
	)
	if err != nil {
		return fmt.Errorf("can't download: %v", err)
	}

	// Read first message.
	resp, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("can't read object info: %v", err)
	}

	notes, err := encrypter.Decrypt(resp.GetInfo().Notes)
	if err != nil {
		return fmt.Errorf("can't process notes from response: %v", err)
	}

	// Recieve object data.
	buf := new(bytes.Buffer)
	for i := uint64(1); ; i++ {
		msg, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("can't download bin data: %v", err)
		}
		data, err := encrypter.DecryptBlock(msg.GetChunk().Data, i)
		if err != nil {
			return fmt.Errorf("can't process data from stream: %v", err)
		}

		if _, err = buf.Write(data); err != nil {
			return fmt.Errorf("can't proccess chunk: %v", err)
		}
	}
	err = stream.CloseSend()
	if err != nil {
		return fmt.Errorf("can't close the stream: %v", err)
	}

	fmt.Fprintf(os.Stdout, "Record\n  name : %v\n  notes: %v\n--------------------\n%v",
		name, string(notes), buf.String())
	return nil
}
