// Package vaultpass provides a vault of blob objects.
package vaultblob

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/alukart32/yandex/practicum/passkee/internal/vault/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// contentEncrypter defines the vault content encryptor.
type contentEncrypter interface {
	Encrypt(plaintext []byte) ([]byte, error)
	EncryptBlock(plaintext []byte, blockNo uint64) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	DecryptBlock(ciphertext []byte, blockNo uint64) ([]byte, error)
}

// vault represents the blob objects vault.
type vault struct {
	enc  contentEncrypter
	pool *pgxpool.Pool
}

// Vault returns a new blob objects vault.
func Vault(pool *pgxpool.Pool, encrypter contentEncrypter) (*vault, error) {
	if pool == nil {
		return nil, fmt.Errorf("nil postgres pool")
	}
	if encrypter == nil {
		return nil, fmt.Errorf("nil vault encrypter")
	}

	return &vault{
		enc:  encrypter,
		pool: pool,
	}, nil
}

// blobModel represents blob object record.
type blobModel struct {
	Meta  blobMeta
	ID    string
	Blob  []byte
	Notes []byte
}

// blobMeta represents blob object meta info.
type blobMeta struct {
	UserID string
	Typ    string
	Name   []byte
}

// Save saves a new blob object.
func (v *vault) Save(ctx context.Context, blob models.Blob) error {
	var (
		err   error
		notes []byte
	)
	if len(blob.Notes) != 0 {
		notes, err = v.enc.Encrypt(blob.Notes)
		if err != nil {
			return fmt.Errorf("can't prepare notes for storing: %v", err)
		}
	}
	data, err := v.encBlob(ctx, blob.Data)
	if err != nil {
		return fmt.Errorf("can't prepare data for storing: %v", err)
	}

	model := blobModel{
		Meta: blobMeta{
			UserID: blob.Meta.Obj.UserID,
			Typ:    blob.Meta.Typ.T,
			Name:   blob.Meta.Obj.Name,
		},
		ID:    uuid.New().String(),
		Blob:  data,
		Notes: notes,
	}
	return v.save(ctx, model)
}

func (v *vault) save(ctx context.Context, model blobModel) error {
	tx, err := v.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:       pgx.RepeatableRead,
		AccessMode:     pgx.ReadWrite,
		DeferrableMode: pgx.NotDeferrable,
	})
	if err != nil {
		return fmt.Errorf("can't start transaction: %v", err.Error())
	}
	defer func() {
		err = v.finishTx(ctx, tx, err)
	}()

	const query = `INSERT INTO blob_objects(id, user_id, name, typ, blob, notes)
	VALUES ($1, $2, $3, $4, $5, $6)`

	_, err = tx.Exec(ctx, query,
		model.ID,
		model.Meta.UserID,
		model.Meta.Name,
		model.Meta.Typ,
		base64.StdEncoding.EncodeToString(model.Blob),
		base64.StdEncoding.EncodeToString(model.Notes),
	)
	return err
}

// Get gets the blob object.
func (v *vault) Get(ctx context.Context, meta models.BlobMeta) (models.Blob, error) {
	model, err := v.get(ctx, blobMeta{meta.Obj.UserID, meta.Typ.T, meta.Obj.Name})
	if err != nil {
		return models.Blob{}, err
	}

	blob, err := v.decBlob(ctx, model.Blob)
	if err != nil {
		return models.Blob{}, err
	}
	var notes []byte
	if len(model.Notes) > 0 {
		notes, err = v.enc.Decrypt([]byte(model.Notes))
		if err != nil {
			return models.Blob{}, err
		}
	}

	return models.Blob{
		Meta:  meta,
		Data:  blob,
		Notes: notes,
	}, nil
}

func (v *vault) get(ctx context.Context, meta blobMeta) (blobModel, error) {
	const query = `SELECT * FROM blob_objects WHERE user_id = $1 AND typ = $2 AND name = $3`
	row := v.pool.QueryRow(ctx, query,
		meta.UserID,
		meta.Typ,
		meta.Name,
	)

	var m blobModel
	err := row.Scan(&m.ID, &m.Meta.UserID, &m.Meta.Name, &m.Meta.Typ, &m.Blob, &m.Notes)
	if err != nil {
		return blobModel{}, err
	}

	blob, err := decodeBase64(m.Blob)
	if err != nil {
		return blobModel{}, err
	}
	m.Blob = blob

	var notes []byte
	if len(m.Notes) != 0 {
		notes, err = decodeBase64(m.Notes)
		if err != nil {
			return blobModel{}, err
		}

	}
	m.Notes = notes

	return m, nil
}

// Index lists blob objects.
func (v *vault) Index(ctx context.Context, userID string, typ models.BlobType) ([]models.Blob, error) {
	names, err := v.listNames(ctx, userID, typ.T)
	if err != nil {
		return nil, err
	}

	records := make([]models.Blob, len(names))
	for i, n := range names {
		records[i] = models.Blob{
			Meta: models.BlobMeta{
				Obj: models.ObjectMeta{
					Name: n,
				},
				Typ: typ,
			},
		}
	}
	return records, nil
}

func (v *vault) listNames(ctx context.Context, userID string, typ string) ([][]byte, error) {
	tx, err := v.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:       pgx.RepeatableRead,
		AccessMode:     pgx.ReadWrite,
		DeferrableMode: pgx.NotDeferrable,
	})
	if err != nil {
		return nil, fmt.Errorf("can't start transaction: %v", err.Error())
	}
	defer func() {
		err = v.finishTx(ctx, tx, err)
	}()

	const query = `SELECT name FROM blob_objects WHERE user_id = $1 AND typ = $2`
	rows, err := tx.Query(ctx, query, userID, typ)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	names := make([][]byte, 0)
	for rows.Next() {
		var name []byte
		if err = rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if rows.Err() != nil {
		return nil, err
	}
	return names, err
}

// Update updates the blob object.
func (v *vault) Update(ctx context.Context, meta models.BlobMeta, data models.Blob) error {
	if len(data.Meta.Obj.Name) == 0 && len(data.Notes) == 0 {
		return fmt.Errorf("nothing to update")
	}
	var err error

	var newNotes []byte
	if len(data.Notes) != 0 {
		newNotes, err = v.enc.Encrypt(data.Notes)
		if err != nil {
			return fmt.Errorf("can't prepare new notes for storing: %v", err)
		}
	}

	return v.update(ctx,
		blobMeta{
			UserID: meta.Obj.UserID,
			Typ:    meta.Typ.T,
			Name:   meta.Obj.Name,
		},
		blobModel{
			Meta: blobMeta{
				Name: data.Meta.Obj.Name,
			},
			Notes: newNotes,
		})
}

func (v *vault) update(ctx context.Context, meta blobMeta, model blobModel) error {
	tx, err := v.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:       pgx.RepeatableRead,
		AccessMode:     pgx.ReadWrite,
		DeferrableMode: pgx.NotDeferrable,
	})
	if err != nil {
		return fmt.Errorf("can't start transaction: %v", err.Error())
	}
	defer func() {
		err = v.finishTx(ctx, tx, err)
	}()

	var (
		fieldOrder = 0
		args       []any
		qb         strings.Builder
	)
	qb.WriteString("UPDATE blob_objects SET ")
	if len(model.Meta.Name) != 0 {
		fieldOrder++

		qb.WriteString(fmt.Sprintf("name = $%d", fieldOrder))
		args = append(args, model.Meta.Name)
	}
	if len(model.Notes) != 0 {
		if fieldOrder > 0 {
			qb.WriteString(", ")
		}
		fieldOrder++

		qb.WriteString(fmt.Sprintf("notes = $%d", fieldOrder))
		args = append(args, base64.StdEncoding.EncodeToString(model.Notes))
	}
	if fieldOrder == 0 {
		return fmt.Errorf("no data to update")
	}

	qb.WriteString(fmt.Sprintf(" WHERE user_id = $%d AND name = $%d",
		fieldOrder+1, fieldOrder+2))
	args = append(args, meta.UserID, meta.Name)

	_, err = tx.Exec(ctx, qb.String(), args...)
	return err
}

// Delete deletes the blob object.
func (v *vault) Delete(ctx context.Context, meta models.BlobMeta) error {
	const query = `DELETE FROM blob_objects WHERE
	user_id = $1 AND typ = $2 AND name = $3`
	_, err := v.pool.Exec(ctx, query,
		meta.Obj.UserID,
		meta.Typ.T,
		meta.Obj.Name,
	)
	return err
}

const maxChunkSize = 4096

func (v *vault) decBlob(ctx context.Context, d []byte) ([]byte, error) {
	data := bytes.NewBuffer(d)
	blocks := new(bytes.Buffer)

	chunk := make([]byte, maxChunkSize+28) // maxChunkSize + nonce + auth tag
	for i := uint64(0); ; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		_, err := data.Read(chunk)
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			break
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		block, err := v.enc.DecryptBlock(chunk, i)
		if err != nil {
			return nil, err
		}
		blocks.Write(block)
	}
	return blocks.Bytes(), nil
}

func (v *vault) encBlob(ctx context.Context, d []byte) ([]byte, error) {
	data := bytes.NewBuffer(d)
	blocks := new(bytes.Buffer)

	chunk := make([]byte, maxChunkSize)
	for i := uint64(0); ; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		_, err := data.Read(chunk)
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			break
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		block, err := v.enc.EncryptBlock(chunk, i)
		if err != nil {
			return nil, err
		}
		blocks.Write(block)
	}
	return blocks.Bytes(), nil
}

// finishTx rollbacks transaction if error is provided.
// If err is nil transaction is committed.
func (v *vault) finishTx(ctx context.Context, tx pgx.Tx, err error) error {
	if err != nil {
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			return errors.Join(err, rollbackErr)
		}
		return err
	} else {
		if commitErr := tx.Commit(ctx); commitErr != nil {
			return fmt.Errorf("failed to commit tx: %v", err)
		}
		return nil
	}
}

func decodeBase64(src []byte) ([]byte, error) {
	txt := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
	n, err := base64.StdEncoding.Decode(txt, src)
	if err != nil {
		return nil, err
	}
	return txt[:n], nil
}
