package vaultobject

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/alukart32/yandex/practicum/passkee/internal/vault/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type contentEncrypter interface {
	Encrypt(plaintext []byte) ([]byte, error)
	EncryptBlock(plaintext []byte, blockNo uint64) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	DecryptBlock(ciphertext []byte, blockNo uint64) ([]byte, error)
}

type vault struct {
	enc  contentEncrypter
	pool *pgxpool.Pool

	// Место хранения объектов.
	// Полный путь файла, каждого объекта, состоит из dir/userID/object_id.
	dir string
}

func Vault(encrypter contentEncrypter, pool *pgxpool.Pool) *vault {
	return &vault{
		enc:  encrypter,
		pool: pool,
	}
}

type objectInfo struct {
	ID     string
	UserID string
	Name   string
	Typ    string
	Notes  string
	URI    string
}

func (v *vault) Save(ctx context.Context, obj models.Object) error {
	// 1. encrypt
	name, err := v.enc.Encrypt([]byte(obj.Name))
	if err != nil {
		return fmt.Errorf("can't encrypt object name: %v", err)
	}

	var notes string
	if len(obj.Notes) != 0 {
		notesBz, err := v.enc.Encrypt([]byte(obj.Notes))
		if err != nil {
			return fmt.Errorf("can't encrypt object notes: %v", err)
		}
		notes = string(notesBz)
	}

	// Save object info.
	objectID := uuid.New()
	filepath := fmt.Sprintf("%v/%v/%v", v.dir, obj.UserID, objectID.String())
	info := objectInfo{
		objectID.String(),
		obj.UserID,
		string(name),
		obj.Typ.T,
		notes,
		filepath,
	}
	if err := v.saveInfo(ctx, info); err != nil {
		return err
	}

	// Save to file.
	v.writeToFile(ctx, filepath, obj.Data)

	return err
}

func (v *vault) saveInfo(ctx context.Context, info objectInfo) error {
	//TODO:
	const insertObjectInfo = ``

	_, err := v.pool.Exec(ctx, insertObjectInfo,
		info.ID,
		info.UserID,
		info.Name,
		info.Typ,
		info.Notes,
	)

	return err
}

func (v *vault) Get(ctx context.Context, userID string, name string, typ models.ObjectType) (models.Object, error) {
	// Get object info.
	//TODO:
	const getObjectInfo = ``

	row := v.pool.QueryRow(ctx, getObjectInfo,
		userID,
		name,
		typ,
	)

	var info objectInfo
	err := row.Scan(&info.ID, &info.UserID, &info.Name, &info.Typ, &info.Notes, &info.URI)
	if err != nil {
		return models.Object{}, fmt.Errorf("can't scan data: %v", err)
	}

	objType, err := models.ObjectTypeFromString(info.Typ)
	if err != nil {
		return models.Object{}, err
	}

	var notes string
	if len(info.Notes) != 0 {
		notesBz, err := v.enc.Decrypt([]byte(info.Notes))
		if err != nil {
			return models.Object{}, fmt.Errorf("can't decrypt record notes: %v", err)
		}
		notes = string(notesBz)
	}

	// Read from file.
	data, err := v.readFromFile(ctx, info.URI)
	if err != nil {
		return models.Object{}, fmt.Errorf("can't take data by URI: %v", err)
	}

	return models.Object{
		UserID: userID,
		Name:   name,
		Typ:    objType,
		Notes:  notes,
		Data:   data,
	}, nil
}

const maxChunkSize = 4096

func (v *vault) readFromFile(ctx context.Context, filepath string) ([]byte, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// TODO:
	blocks := new(bytes.Buffer)

	fr := bufio.NewReader(file)
	chunk := make([]byte, maxChunkSize)
	for blockNo := uint64(1); ; blockNo++ {
		_, err := fr.Read(chunk)
		if err != nil {
			if err != io.EOF {
				fmt.Println(err)
			}
			break
		}

		// TODO: goroutines
		block, err := v.enc.DecryptBlock(chunk, blockNo)
		if err != nil {
			return nil, err
		}
		blocks.Write(block)
	}

	return blocks.Bytes(), nil
}

func (v *vault) writeToFile(ctx context.Context, filepath string, d []byte) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	// TODO:
	// 1. enc data chunk
	// 2. write chunk to file
	//
	// enc - pipe -> write to file ?
	buf := new(bytes.Buffer)
	_, err = buf.WriteTo(file)
	if err != nil {
		return err
	}
	return nil
}
