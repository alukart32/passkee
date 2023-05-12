package bincmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/objectpb"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func getCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "get [--n name]",
		Short: "Get binary data from vault",
	}
	cmd.RunE = getE

	cmd.Flags().StringVarP(&name, "name", "n", "", "Record name")
	cmd.MarkFlagRequired("name")

	return &cmd
}

func getE(cmd *cobra.Command, args []string) error {
	recordName, err := encrypter.Encrypt([]byte(name))
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %v", err)
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

	streamCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := objectpb.NewObjectVaultClient(conn)
	stream, err := client.DownloadObject(
		sessHandler.AuthContext(streamCtx),
		&objectpb.DownloadObjectRequest{
			Name: recordName,
			Typ:  objectpb.ObjectType_OBJECT_BIN,
		},
	)
	if err != nil {
		return fmt.Errorf("unable to stream: %v, details: %v", err, stream.RecvMsg(nil))
	}

	// Read first message.
	resp, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("can't receive object info: %v", err)
	}

	name, err := encrypter.Decrypt(resp.GetInfo().Name)
	if err != nil {
		return fmt.Errorf("can't decrypt a name from response: %v", err)
	}
	notes, err := encrypter.Decrypt(resp.GetInfo().Notes)
	if err != nil {
		return fmt.Errorf("can't decrypt notes from response: %v", err)
	}
	resp = nil

	// Read object data chunks.
	buf := new(bytes.Buffer)
	for blockNo := uint64(1); ; blockNo++ {
		msg, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return err
			}
		}
		// TODO: goroutines?
		data, err := encrypter.DecryptBlock(msg.GetChunk().Data, blockNo)
		if err != nil {
			return fmt.Errorf("can't decrypt a data chunk from response: %v", err)
		}

		if _, err = buf.Write(data); err != nil {
			return fmt.Errorf("can't proccess a chunk: %v", err)
		}
	}
	err = stream.CloseSend()
	if err != nil {
		return fmt.Errorf("can't close a stream: %v", err)
	}

	// TODO: show downloaded object
	// 1. save to file
	// 2. stdout
	fmt.Fprintf(os.Stdout, "Name: %v\nNotes: %v\n\n%s", name, notes, buf)

	return err
}
