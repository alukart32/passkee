package v1

import (
	"bytes"
	"context"
	"io"
	"log"

	"github.com/alukart32/yandex/practicum/passkee/internal/vault/models"
	"github.com/alukart32/yandex/practicum/passkee/pkg/proto/v1/objectpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func RegisterObjectVaultService(srv *grpc.Server) {
	// TODO:
}

type objectVault interface {
	Save(context.Context, models.Object) error
}

type objectVaultService struct {
	objectpb.UnimplementedObjectVaultServer

	sessProvider sessionProvider
	vault        objectVault
}

const maxObjectSize = 1 << 20 // 1Mb

func (s *objectVaultService) UploadObject(stream objectpb.ObjectVault_UploadObjectServer) error {
	session, err := s.sessProvider.SessionById(sessionFromCtx(stream.Context()))
	if err != nil {
		return status.Errorf(codes.Internal, "session not found")
	}
	encrypter, err := session.DataEncrypter()
	if err != nil {
		return status.Errorf(codes.Internal, "can't prepare session encrypter: %v", err)
	}

	// Receive object info.
	req, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.Unknown, "can't receive object info")
	}

	userID := userIDFromCtx(stream.Context())
	name, err := encrypter.Decrypt(req.GetInfo().Name)
	if err != nil {
		return status.Error(codes.Internal, "can't decrypt a name from request")
	}

	var notes []byte
	if req.GetInfo().Notes != nil {
		notes, err = encrypter.Decrypt(req.GetInfo().Notes)
		if err != nil {
			return status.Error(codes.Internal, "can't decrypt notes from request")
		}
	}

	typ, err := models.ObjectTypeFromString(req.GetInfo().Typ.String())
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid object type: %v", err)
	}

	log.Printf("receive an upload-object request for user %v with name %v and type %v", userID, name, typ)

	// Receive object data.
	buf := bytes.Buffer{}
	objectSize := 0
	for blockNo := uint64(1); ; blockNo++ {
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return status.Error(codes.Unknown, err.Error())
		}

		// Validate uploaded object size.
		objectSize += len(msg.GetChunk().Data)
		if objectSize > maxObjectSize {
			return status.Errorf(codes.InvalidArgument,
				"object is too large: %d > %d", objectSize, maxObjectSize)
		}
		// TODO: goroutines?
		data, err := encrypter.DecryptBlock(msg.GetChunk().Data, blockNo)
		if err != nil {
			return status.Errorf(codes.Internal, "can't decrypt data chunk from response: %v", err)
		}

		if _, err = buf.Write(data); err != nil {
			return status.Errorf(codes.Internal, "can't proccess a chunk: %v", err)
		}
	}

	err = s.vault.Save(stream.Context(), models.Object{
		UserID: userID,
		Name:   string(name),
		Typ:    typ,
		Notes:  string(notes),
		Data:   buf.Bytes(),
	})
	if err != nil {
		return status.Errorf(codes.Internal, "can't save a new object: %v", err)
	}
	err = stream.SendAndClose(&emptypb.Empty{})
	if err != nil {
		return status.Errorf(codes.Unknown, "can't close a stream: %v", err)
	}

	log.Printf("object for user %v with name %v and type %v was saved", userID, name, typ)
	return nil
}
