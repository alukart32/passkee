package v1

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"

	"github.com/alukart32/yandex/practicum/passkee/internal/vault/models"
	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/blobpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// RegisterBlobVaultService registers blobpb.UnimplementedBlobVaultServer implementation.
func RegisterBlobVaultService(srv *grpc.Server, sess sessionProvider, vault blobVault) error {
	if srv == nil {
		return fmt.Errorf("no grpc server to register")
	}
	if sess == nil {
		return fmt.Errorf("no session provider")
	}
	if vault == nil {
		return fmt.Errorf("no vault")
	}

	blobpb.RegisterBlobVaultServer(srv,
		&blobVaultService{
			sessProvider: sess,
			vault:        vault,
		},
	)
	return nil
}

// blobVault defines bin objects vault.
type blobVault interface {
	Save(context.Context, models.Blob) error
	Get(context.Context, models.BlobMeta) (models.Blob, error)
	Index(ctx context.Context, userID string, typ models.BlobType) ([]models.Blob, error)
	Update(ctx context.Context, meta models.BlobMeta, data models.Blob) error
	Delete(context.Context, models.BlobMeta) error
}

// blobVaultService is an implementation of blobpb.UnimplementedBlobVaultServer.
type blobVaultService struct {
	blobpb.UnimplementedBlobVaultServer

	sessProvider sessionProvider
	vault        blobVault
}

const (
	maxObjectSize = 1 << 20 // 1Mb
	maxChunkSize  = 4096    // bytes
)

// Uploads a new data object.
//
// The first message contains the metadata of the object, such as name, type, and optional notes.
// The following messages will contain an object with a data block size of 4096 bytes.
func (s *blobVaultService) UploadObject(stream blobpb.BlobVault_UploadObjectServer) error {
	session, err := s.sessProvider.SessionById(sessionFromCtx(stream.Context()))
	if err != nil {
		return status.Errorf(codes.Internal, "session not found")
	}
	encrypter, err := session.DataEncrypter()
	if err != nil {
		return status.Errorf(codes.Internal, "can't prepare session: %v", err)
	}

	// Receive object info.
	req, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.Unknown,
			"can't receive object info: %v", err)
	}

	name, err := encrypter.Decrypt(req.GetInfo().Name)
	if err != nil {
		return status.Error(codes.Internal,
			"can't process object name from request")
	}
	var notes []byte
	if req.GetInfo().Notes != nil {
		notes, err = encrypter.Decrypt(req.GetInfo().Notes)
		if err != nil {
			return status.Error(codes.Internal,
				"can't process object notes from request")
		}
	}
	objTyp, err := models.ObjectTypeFromString(req.GetInfo().Typ.String())
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid object type: %v", err)
	}

	userID := userIDFromCtx(stream.Context())
	log.Printf("receive an upload-object request for user %v with name %v and type %v",
		userID, string(name), objTyp.T)

	// Receive object data.
	objectSize := 0
	buf := bytes.Buffer{}
	for i := uint64(0); ; i++ {
		msg, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return status.Error(codes.Unknown, err.Error())
		}

		// Validate uploaded object size.
		objectSize += len(msg.GetChunk().Data)
		if objectSize > maxObjectSize {
			return status.Errorf(codes.InvalidArgument,
				"object is too large: %d > %d", objectSize, maxObjectSize)
		}
		data, err := encrypter.DecryptBlock(msg.GetChunk().Data, i)
		if err != nil {
			return status.Errorf(codes.Internal, "can't proccess stream: %v", err)
		}

		if _, err = buf.Write(data); err != nil {
			return status.Errorf(codes.Internal, "can't proccess stream: %v", err)
		}
	}

	err = s.vault.Save(stream.Context(), models.Blob{
		Meta: models.BlobMeta{
			Obj: models.ObjectMeta{
				UserID: userID,
				Name:   name,
			},
			Typ: objTyp,
		},
		Notes: notes,
		Data:  buf.Bytes(),
	})
	if err != nil {
		return status.Errorf(codes.Internal, "can't save a new object: %v", err)
	}
	err = stream.SendAndClose(&emptypb.Empty{})
	if err != nil {
		return status.Errorf(codes.Unknown, "can't close the stream: %v", err)
	}

	log.Printf("object for user %v with name %v and type %v was saved",
		userID, name, objTyp)
	return nil
}

// Downloads the object from vault.
//
// The first message contains the metadata of the object, such as name and optional notes.
// The following messages will contain an object with a data block size of 4096 bytes.
func (s *blobVaultService) DownloadObject(in *blobpb.DownloadObjectRequest, stream blobpb.BlobVault_DownloadObjectServer) error {
	session, err := s.sessProvider.SessionById(sessionFromCtx(stream.Context()))
	if err != nil {
		return status.Errorf(codes.Internal, "session not found")
	}
	encrypter, err := session.DataEncrypter()
	if err != nil {
		return status.Errorf(codes.Internal, "can't prepare session: %v", err)
	}

	// Receive object info.
	recordName, err := encrypter.Decrypt([]byte(in.Name))
	if err != nil {
		return status.Error(codes.Internal, "can't process record name from request")
	}
	objTyp, err := models.ObjectTypeFromString(in.Typ.String())
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid object type: %v", err)
	}

	userID := userIDFromCtx(stream.Context())
	log.Printf("receive an download-object request for user %v with name %v and type %v",
		userID, recordName, objTyp)

	blob, err := s.vault.Get(stream.Context(), models.BlobMeta{
		Obj: models.ObjectMeta{
			UserID: userID,
			Name:   recordName,
		},
		Typ: objTyp,
	})
	if err != nil {
		return status.Errorf(codes.Unknown, "can't find object record: %v", err)
	}

	var notes []byte
	if len(blob.Notes) != 0 {
		notes, err = encrypter.Encrypt(blob.Notes)
		if err != nil {
			return status.Errorf(codes.Internal,
				"can't prepare record notes for response: %v", err)
		}
	}

	// Send object info.
	err = stream.Send(&blobpb.DownloadObjectResponse{
		Data: &blobpb.DownloadObjectResponse_Info{
			Info: &blobpb.DownloadObjectResponse_ObjectInfo{
				Notes: notes,
			},
		},
	})
	if err != nil {
		return status.Errorf(codes.Unknown, "can't send object info: %v", err.Error())
	}

	chunk := make([]byte, maxChunkSize)
	buf := bytes.NewBuffer(blob.Data)
	for i := uint64(1); buf.Len() > 0; i++ {
		_, err := buf.Read(chunk)
		if err != nil {
			return status.Errorf(codes.Internal,
				"can't prepare data for sending: %v", err.Error())
		}

		block, err := encrypter.EncryptBlock(chunk, i)
		if err != nil {
			return status.Errorf(codes.Internal,
				"can't prepare data for sending: %v", err.Error())
		}

		err = stream.Send(&blobpb.DownloadObjectResponse{
			Data: &blobpb.DownloadObjectResponse_Chunk{
				Chunk: &blobpb.Chunk{
					Data: block,
				},
			},
		})
		if err != nil {
			return status.Errorf(codes.Internal,
				"can't stream chunk: %v", err.Error())
		}
	}
	log.Printf("object for user %v with name %v and type %v was downloaded",
		userID, recordName, objTyp)
	return nil
}

// Index lists all bin objects by name.
func (s *blobVaultService) IndexObjects(ctx context.Context, in *blobpb.IndexObjectsRequest) (
	*blobpb.IndexObjectsResponse, error) {
	objTyp, err := models.ObjectTypeFromString(in.Typ.String())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid object type: %v", err)
	}

	records, err := s.vault.Index(ctx, userIDFromCtx(ctx), objTyp)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't index objects: %v", err)
	}
	if len(records) == 0 {
		return &blobpb.IndexObjectsResponse{}, nil
	}

	session, err := s.sessProvider.SessionById(sessionFromCtx(ctx))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "session not found")
	}
	encrypter, err := session.DataEncrypter()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't prepare session: %v", err)
	}

	names := make([][]byte, len(records))
	for i, v := range records {
		name, err := encrypter.Encrypt(v.Meta.Obj.Name)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't prepare data for sending: %v", err)
		}
		names[i] = name
	}
	return &blobpb.IndexObjectsResponse{Names: names}, nil
}

// UpdateObjectInfo updates the object details.
func (s *blobVaultService) UpdateObjectInfo(ctx context.Context, in *blobpb.UpdateObjectInfoRequest) (*emptypb.Empty, error) {
	if in.Info.Name == nil && in.Info == nil {
		return nil, status.Errorf(codes.InvalidArgument, "nothing to update")
	}

	session, err := s.sessProvider.SessionById(sessionFromCtx(ctx))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "session not found")
	}
	encrypter, err := session.DataEncrypter()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't prepare session: %v", err)
	}

	recordName, err := encrypter.Decrypt([]byte(in.Name))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't process record name from request: %v")
	}
	objTyp, err := models.ObjectTypeFromString(in.Typ.String())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid object type: %v", err)
	}

	var newName []byte
	if len(in.Info.Name) != 0 {
		newName, err = encrypter.Decrypt(in.Info.Name)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't process a new name from request: %v")
		}
	}
	var newNotes []byte
	if len(in.Info.Notes) != 0 {
		newNotes, err = encrypter.Decrypt(in.Info.Notes)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "can't process new notes from request: %v")
		}
	}

	userID := userIDFromCtx(ctx)
	err = s.vault.Update(ctx, models.BlobMeta{
		Obj: models.ObjectMeta{
			UserID: userID,
			Name:   recordName,
		},
		Typ: objTyp,
	}, models.Blob{
		Meta: models.BlobMeta{
			Obj: models.ObjectMeta{
				Name: newName,
			},
		},
		Notes: newNotes,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't update object info: %v", err)
	}
	return &emptypb.Empty{}, nil
}

// DeleteObject deletes the bin object.
func (s *blobVaultService) DeleteObject(ctx context.Context, in *blobpb.DeleteObjectRequest) (*emptypb.Empty, error) {
	session, err := s.sessProvider.SessionById(sessionFromCtx(ctx))
	if err != nil {
		return nil, status.Error(codes.Internal, "session not found")
	}
	encrypter, err := session.DataEncrypter()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't prepare session: %v", err)
	}

	recordName, err := encrypter.Decrypt([]byte(in.Name))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't process record name from request: %v")
	}
	objTyp, err := models.ObjectTypeFromString(in.Typ.String())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid object type: %v", err)
	}

	userID := userIDFromCtx(ctx)
	err = s.vault.Delete(ctx, models.BlobMeta{
		Obj: models.ObjectMeta{
			UserID: userID,
			Name:   recordName,
		},
		Typ: objTyp,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can't delete object record: %v", err)
	}
	return &emptypb.Empty{}, nil
}
