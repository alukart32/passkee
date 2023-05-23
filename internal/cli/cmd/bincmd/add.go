package bincmd

import (
	"bufio"
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

func addCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "add filepath",
		Short: "put the new binary data in vault",
		Example: `add -n record_name filepath
add -n record_name --notes "extra info" filepath`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.MaximumNArgs(1)(cmd, args); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.RunE = addE

	cmd.Flags().StringVarP(&name, "name", "n", "", "Name of the new record")
	cmd.MarkFlagRequired("name")
	cmd.Flags().StringVarP(&notes, "notes", "", "", "Extra notes")

	return &cmd
}

var name, notes string

const (
	maxSize    = 1 << 20 // 1 MB
	bufferSize = 4096    // bytes

	rateLimitPeriod = time.Minute
	rateLimit       = 200 // most 200 requests in one minute
)

func addE(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("filepath wasn't provided")
	}
	filepath := args[0]

	// Read the file and encrypt its data in blocks.
	blocks, err := readFile(filepath)
	if err != nil {
		return err
	}

	encName, err := encrypter.Encrypt([]byte(name))
	if err != nil {
		return fmt.Errorf("can't prepare data for sending: %v", err)
	}
	var encNotes []byte
	if len(notes) != 0 {
		encNotes, err = encrypter.Encrypt([]byte(notes))
		if err != nil {
			return fmt.Errorf("can't prepare data for sending: %v", err)
		}
	}

	// Prepare gRPC client.
	conn, err := grpc.Dial(
		sessHandler.RemoteAddr(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()

	client := blobpb.NewBlobVaultClient(conn)
	uploadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.UploadObject(sessHandler.AuthContext(uploadCtx))
	if err != nil {
		return fmt.Errorf("can't stream: %v", err)
	}
	// Send the object info.
	err = stream.Send(&blobpb.UploadObjectRequest{
		Data: &blobpb.UploadObjectRequest_Info{
			Info: &blobpb.UploadObjectRequest_ObjectInfo{
				Name:  encName,
				Typ:   blobpb.ObjectType_OBJECT_BIN,
				Notes: encNotes,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("can't upload: %v, details: %v", err, stream.RecvMsg(nil))
	}

	quotas := make(chan time.Time, rateLimit)
	go func() {
		tick := time.NewTicker(rateLimitPeriod / rateLimit)
		defer tick.Stop()
		for t := range tick.C {
			select {
			case quotas <- t:
			case <-stream.Context().Done():
				return
			default:
			}
		}
	}()

	// Send chunks.
	for _, b := range blocks {
		<-quotas
		err := stream.Send(&blobpb.UploadObjectRequest{
			Data: &blobpb.UploadObjectRequest_Chunk{
				Chunk: &blobpb.Chunk{
					Data: b,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("can't stream: %v, details: %v", err, stream.RecvMsg(nil))
		}
	}
	_, err = stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("can't close the stream: %v", err)
	}

	fmt.Println("object uploaded")
	return nil
}

func readFile(filepath string) ([][]byte, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("can't open the file %v", filepath)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("can't read the file properties - %v", err)
	}
	size := fi.Size()
	if size > maxSize {
		return nil, fmt.Errorf("unexpected file size %v, want %v", size, maxSize)
	}

	// Read and encrypt file data in blocks.
	fr := bufio.NewReader(f)
	blocks := make([][]byte, 1+(size-1)/bufferSize)
	for i := uint64(0); ; i++ {
		tmp := make([]byte, bufferSize)
		_, err := fr.Read(tmp)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return nil, err
			}
		}

		b, err := encrypter.EncryptBlock(tmp, i)
		if err != nil {
			return nil, fmt.Errorf("can't encrypt object data: %v", err)
		}

		blocks[i] = b
	}

	return blocks, err
}
