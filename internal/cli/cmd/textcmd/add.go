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

	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/objectpb"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func addCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "add [--n name]([-notes])([-f filepath]) value",
		Short: "Put the new text in vault",
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

	client := objectpb.NewObjectVaultClient(conn)
	stream, err := client.UploadObject(sessHandler.AuthContext(streamCtx))
	if err != nil {
		return fmt.Errorf("unable to stream: %v", err)
	}

	// Send the object info.
	err = stream.Send(&objectpb.UploadObjectRequest{
		Data: &objectpb.UploadObjectRequest_Info{
			Info: &objectpb.UploadObjectRequest_ObjectInfo{
				Name:  encName,
				Typ:   objectpb.ObjectType_OBJECT_TEXT,
				Notes: encNotes,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("unable to stream: %v, details: %v", err, stream.RecvMsg(nil))
	}

	// Send data chunks.
	for _, b := range blocks {
		// TODO: add rate limiting
		err := stream.Send(&objectpb.UploadObjectRequest{
			Data: &objectpb.UploadObjectRequest_Chunk{
				Chunk: &objectpb.Chunk{
					Data: b,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("unable to stream: %v, details: %v", err, stream.RecvMsg(nil))
		}
	}
	err = stream.CloseSend()
	if err != nil {
		return fmt.Errorf("can't close stream: %v", err)
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
		return nil, fmt.Errorf("unexpected file size %v, want %v", size, maxSize)
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
