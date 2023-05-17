package vaultblob

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/alukart32/yandex/practicum/passkee/internal/vault/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
}

func Vault(encrypter contentEncrypter, pool *pgxpool.Pool) *vault {
	return &vault{
		enc:  encrypter,
		pool: pool,
	}
}

type blobModel struct {
	Meta  blobMeta
	ID    string
	Blob  []byte
	Notes []byte
}

type blobMeta struct {
	UserID string
	Typ    string
	Name   []byte
}

func (v *vault) Save(ctx context.Context, blob models.Blob) error {
	name, err := v.enc.Encrypt(blob.Meta.Obj.Name)
	if err != nil {
		return fmt.Errorf("can't prepare name for storing: %v", err)
	}
	var notes []byte
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
			Name:   name,
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
	VALUES ($1, $2, $3, $4, $5)`

	_, err = tx.Exec(ctx, query,
		model.ID,
		model.Meta.UserID,
		model.Meta.Name,
		model.Meta.Typ,
		model.Blob,
		model.Notes,
	)
	return err
}

func (v *vault) Get(ctx context.Context, meta models.BlobMeta) (models.Blob, error) {
	recordName, err := v.enc.Encrypt(meta.Obj.Name)
	if err != nil {
		return models.Blob{}, fmt.Errorf("can't process record name: %v", err)
	}
	model, err := v.get(ctx, blobMeta{
		meta.Obj.UserID,
		meta.Typ.T,
		recordName})
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
	return m, nil
}

func (v *vault) Index(ctx context.Context, userID string, typ models.BlobType) ([]models.Blob, error) {
	records, err := v.index(ctx, userID, typ.T)
	if err != nil {
		return nil, err
	}

	objects := make([]models.Blob, len(records))
	for i, r := range records {
		name, err := v.enc.Decrypt(r.Meta.Name)
		if err != nil {
			return nil, err
		}
		typ, err := models.ObjectTypeFromString(r.Meta.Typ)
		if err != nil {
			return nil, err
		}

		objects[i] = models.Blob{
			Meta: models.BlobMeta{
				Obj: models.ObjectMeta{
					Name: name,
				},
				Typ: typ,
			},
		}
	}
	return objects, nil
}

func (v *vault) index(ctx context.Context, userID string, typ string) ([]blobModel, error) {
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

	const query = `SELECT name, typ FROM blob_objects WHERE user_id = $1 AND typ = $2`
	rows, err := tx.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]blobModel, 0)
	for rows.Next() {
		var m blobModel
		if err = rows.Scan(&m.Meta.Name, &m.Meta.Typ); err != nil {
			return nil, err
		}
		records = append(records, m)
	}
	if rows.Err() != nil {
		return nil, err
	}
	return records, err
}

func (v *vault) Update(ctx context.Context, meta models.BlobMeta, data models.Blob) error {
	if len(data.Meta.Obj.Name) == 0 && len(data.Data) == 0 && len(data.Notes) == 0 {
		return fmt.Errorf("nothing to update")
	}

	recordName, err := v.enc.Encrypt(meta.Obj.Name)
	if err != nil {
		return fmt.Errorf("can't prepare record name: %v", err)
	}
	var newName []byte
	if len(data.Meta.Obj.Name) != 0 {
		newName, err = v.enc.Encrypt(data.Meta.Obj.Name)
		if err != nil {
			return fmt.Errorf("can't prepare new name for storing: %v", err)
		}
	}
	var newNotes []byte
	if len(data.Notes) != 0 {
		newNotes, err = v.enc.Encrypt(data.Notes)
		if err != nil {
			return fmt.Errorf("can't prepare new notes for storing: %v", err)
		}
	}
	var newBlob []byte
	if len(data.Data) != 0 {
		newBlob, err = v.encBlob(ctx, data.Data)
		if err != nil {
			return fmt.Errorf("can't prepare new data for storing: %v", err)
		}
	}

	return v.update(ctx,
		blobMeta{
			UserID: meta.Obj.UserID,
			Typ:    meta.Typ.T,
			Name:   recordName,
		},
		blobModel{
			Meta: blobMeta{
				Name: newName,
			},
			Blob:  newBlob,
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

	var qb strings.Builder
	qb.WriteString("UPDATE blob_objects")
	if len(model.Meta.Name) != 0 {
		qb.WriteString(" SET name = $1")
	}
	if len(model.Blob) != 0 {
		qb.WriteString(" SET blob = $2")
	}
	if len(model.Notes) != 0 {
		qb.WriteString(" SET notes = $3")
	}
	qb.WriteString(" WHERE user_id = $4 AND typ = $5")

	_, err = tx.Exec(ctx, qb.String(),
		model.Meta.Name,
		model.Blob,
		model.Notes,
		meta.UserID,
		meta.Typ,
	)
	return err
}

func (v *vault) Delete(ctx context.Context, meta models.BlobMeta) error {
	recordName, err := v.enc.Encrypt(meta.Obj.Name)
	if err != nil {
		return fmt.Errorf("can't process a record name: %v", err)
	}

	const query = `DELETE blob_objects WHERE user_id = $1 AND typ = $2 AND name = $3`
	_, err = v.pool.Exec(ctx, query,
		meta.Obj.UserID,
		meta.Typ.T,
		recordName,
	)
	return err
}

const maxChunkSize = 4096

func (v *vault) decBlob(ctx context.Context, d []byte) ([]byte, error) {
	blocks := new(bytes.Buffer)

	data := bytes.NewBuffer(d)
	chunk := make([]byte, maxChunkSize)
	for i := uint64(1); ; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		_, err := data.Read(chunk)
		if err != nil {
			if err != io.EOF {
				fmt.Println(err)
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
	for i := uint64(1); ; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		_, err := data.Read(chunk)
		if err != nil {
			if err != io.EOF {
				fmt.Println(err)
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

func (v *vault) encBlob2(ctx context.Context, d []byte) ([]byte, error) {
	type chunk struct {
		no   uint64
		data []byte
	}
	chunks := make(chan chunk, 1)
	errCh := make(chan error, 1)
	stopCh := make(chan struct{}, 1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		var err error
		defer func() {
			if err != nil {
				errCh <- err
			}
			close(chunks)
			wg.Done()
		}()

		buf := bytes.NewBuffer(d)
		c := make([]byte, maxChunkSize)
		for i := uint64(1); ; i++ {
			select {
			case <-ctx.Done():
				err = ctx.Err()
				return
			case <-stopCh:
				return
			default:
			}
			_, err = buf.Read(c)
			if err != nil {
				return
			}
			chunks <- chunk{
				no:   i,
				data: c,
			}
		}
	}()

	blocks := new(bytes.Buffer)

	wg.Add(1)
	go func() {
		var err error
		defer func() {
			if err != nil {
				errCh <- err
			}
			wg.Done()
		}()

		for chunk := range chunks {
			select {
			case <-ctx.Done():
				err = ctx.Err()
				return
			case <-stopCh:
				return
			default:
			}

			block, err := v.enc.EncryptBlock(chunk.data, chunk.no)
			if err != nil {
				return
			}
			blocks.Write(block)
		}
	}()

	// Wait until all chunks are processed.
	go func() {
		wg.Wait()
		close(errCh)
	}()

	if err := <-errCh; err != nil {
		close(stopCh)
		return nil, err
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
