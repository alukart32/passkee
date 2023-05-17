package textcmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/blobpb"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func addCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "add",
		Short: "put the new text in vault",
		Example: `add -n demo_text -f filepath
add -n demo_text "some text"`,
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

var name, notes, filepath string

const (
	maxSize    = 1 << 20 // bytes
	bufferSize = 4096    // bytes

	rateLimitPeriod = time.Minute
	rateLimit       = 200 // most 200 requests in one minute
)

func addE(cmd *cobra.Command, args []string) error {
	var (
		blocks [][]byte
		err    error
	)
	if len(filepath) != 0 {
		// Read the file and encrypt its data in blocks.
		blocks, err = readFile(filepath)
		if err != nil {
			return err
		}
	} else {
		if len(args[0]) == 0 {
			return fmt.Errorf("no text was provided")
		}
		blocks, err = encData(args[0])
		if err != nil {
			return err
		}
	}

	encName, err := encrypter.Encrypt([]byte(name))
	if err != nil {
		return fmt.Errorf("can't encrypt object name: %v", err)
	}
	var encNotes []byte
	if len(notes) != 0 {
		encNotes, err = encrypter.Encrypt([]byte(notes))
		if err != nil {
			return fmt.Errorf("can't encrypt object notes: %v", err)
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

	streamCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := blobpb.NewBlobVaultClient(conn)
	stream, err := client.UploadObject(sessHandler.AuthContext(streamCtx))
	if err != nil {
		return fmt.Errorf("can't upload text: %v", err)
	}

	// Send the object info.
	err = stream.Send(&blobpb.UploadObjectRequest{
		Data: &blobpb.UploadObjectRequest_Info{
			Info: &blobpb.UploadObjectRequest_ObjectInfo{
				Name:  encName,
				Typ:   blobpb.ObjectType_OBJECT_TEXT,
				Notes: encNotes,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("can't send text info: %v, details: %v", err, stream.RecvMsg(nil))
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

	// Send data chunks.
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
	err = stream.CloseSend()
	if err != nil {
		return fmt.Errorf("can't close the stream: %v", err)
	}

	log.Printf("object was uploaded")
	return nil
}

func encData(data string) ([][]byte, error) {
	size := len(data)

	if size < bufferSize {
		block, err := encrypter.Encrypt([]byte(data))
		if err != nil {
			return nil, fmt.Errorf("can't encrypt: %v", err)
		}
		return [][]byte{block}, nil
	}

	blocks := make([][]byte, 1+(size-1)/bufferSize)
	r := strings.NewReader(data)
	for i := uint64(1); ; i++ {
		tmp := make([]byte, bufferSize)
		_, err := r.Read(tmp)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return nil, err
			}
		}

		b, err := encrypter.EncryptBlock(tmp, i)
		if err != nil {
			return nil, fmt.Errorf("can't encrypt: %v", err)
		}
		blocks = append(blocks, b)
	}

	return blocks, nil
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
		return nil, fmt.Errorf("file size %v > %v", size, maxSize)
	}

	// Read and encrypt file data in blocks.
	fr := bufio.NewReader(f)
	blocks := make([][]byte, 1+(size-1)/bufferSize)
	for i := uint64(1); ; i++ {
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
			return nil, fmt.Errorf("can't encrypt: %v", err)
		}

		blocks = append(blocks, b)
	}

	return blocks, err
}
