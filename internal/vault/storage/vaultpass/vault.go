// Package vaultpass provides a vault of password pairs.
package vaultpass

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/alukart32/yandex/practicum/passkee/internal/vault/models"
	"github.com/alukart32/yandex/practicum/passkee/internal/vault/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// contentEncrypter defines the vault content encryptor.
type contentEncrypter interface {
	Encrypt(plaintext []byte) ([]byte, error)
	EncryptBlock(plaintext []byte, blockNo uint64) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	DecryptBlock(ciphertext []byte, blockNo uint64) ([]byte, error)
}

// vault represents the password pairs vault.
type vault struct {
	enc  contentEncrypter
	pool *pgxpool.Pool
}

// Vault returns a new password pairs vault.
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

// Save saves a new password pair.
func (v *vault) Save(ctx context.Context, pass models.Password) error {
	data, err := v.enc.Encrypt(pass.Data)
	if err != nil {
		return fmt.Errorf("can't prepare data for storing: %v", err)
	}
	var notes []byte
	if len(pass.Notes) != 0 {
		b, err := v.enc.Encrypt(pass.Notes)
		if err != nil {
			return fmt.Errorf("can't prepare notes for storing: %v", err)
		}
		notes = b
	}

	err = v.save(ctx, passwordModel{
		UserID: pass.Meta.UserID,
		Name:   pass.Meta.Name,
		Data:   data,
		Notes:  notes,
	})
	return err
}

// passwordModel represents password pair record.
type passwordModel struct {
	ID     string
	UserID string
	Name   []byte
	Data   []byte
	Notes  []byte
}

func (v *vault) save(ctx context.Context, model passwordModel) error {
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

	const query = `INSERT INTO passwords(id, user_id, name, data, notes)
	VALUES ($1, $2, $3, $4, $5)`

	_, err = tx.Exec(ctx, query,
		uuid.New(),
		model.UserID,
		model.Name,
		base64.StdEncoding.EncodeToString(model.Data),
		base64.StdEncoding.EncodeToString(model.Notes),
	)

	var pgErr *pgconn.PgError
	if err != nil && errors.As(err, &pgErr) {
		if pgerrcode.IsIntegrityConstraintViolation(pgErr.SQLState()) &&
			pgErr.SQLState() == pgerrcode.UniqueViolation {
			return storage.ErrNameUniqueViolation
		}
	}
	return err
}

// Get gets the password pair.
func (v *vault) Get(ctx context.Context, meta models.ObjectMeta) (models.Password, error) {
	model, err := v.get(ctx, meta.UserID, meta.Name)
	if err != nil {
		return models.Password{}, err
	}

	data, err := v.enc.Decrypt(model.Data)
	if err != nil {
		return models.Password{}, err
	}
	var notes []byte
	if len(model.Notes) != 0 {
		notes, err = v.enc.Decrypt(model.Notes)
		if err != nil {
			return models.Password{}, err
		}
	}

	return models.Password{
		Meta:  meta,
		Data:  data,
		Notes: notes,
	}, nil
}

func (v *vault) get(ctx context.Context, userID string, recordName []byte) (passwordModel, error) {
	const query = `SELECT * FROM passwords WHERE user_id = $1 AND name = $2`
	row := v.pool.QueryRow(ctx, query, userID, recordName)

	var m passwordModel
	err := row.Scan(&m.ID, &m.UserID, &m.Name, &m.Data, &m.Notes)
	if err != nil {
		return passwordModel{}, err
	}

	data, err := decodeBase64(m.Data)
	if err != nil {
		return passwordModel{}, err
	}
	m.Data = data

	var notes []byte
	if len(m.Notes) != 0 {
		notes, err = decodeBase64(m.Notes)
		if err != nil {
			return passwordModel{}, err
		}
	}
	m.Notes = notes

	return m, nil
}

// Index lists password pairs.
func (v *vault) Index(ctx context.Context, userID string) ([]models.Password, error) {
	names, err := v.listNames(ctx, userID)
	if err != nil {
		return nil, err
	}

	passwords := make([]models.Password, len(names))
	for i, n := range names {
		passwords[i] = models.Password{
			Meta: models.ObjectMeta{
				Name: n,
			},
		}
	}
	return passwords, nil
}

func (v *vault) listNames(ctx context.Context, userID string) ([][]byte, error) {
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

	const query = `SELECT name FROM passwords WHERE user_id = $1`
	rows, err := tx.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	names := make([][]byte, 0)
	for rows.Next() {
		var m passwordModel
		if err = rows.Scan(&m.Name); err != nil {
			return nil, err
		}
		names = append(names, m.Name)
	}
	if rows.Err() != nil {
		return nil, err
	}
	return names, err
}

// Reset resets the password pair.
func (v *vault) Reset(ctx context.Context, meta models.ObjectMeta, data models.Password) error {
	if len(data.Meta.Name) == 0 && len(data.Data) == 0 && len(data.Notes) == 0 {
		return fmt.Errorf("nothing to update")
	}
	var err error

	var newData []byte
	if len(data.Data) != 0 {
		newData, err = v.enc.Encrypt(data.Data)
		if err != nil {
			return fmt.Errorf("can't prepare new data for storing: %v", err)
		}
	}
	var newNotes []byte
	if len(data.Notes) != 0 {
		newNotes, err = v.enc.Encrypt(data.Notes)
		if err != nil {
			return fmt.Errorf("can't prepare new notes for storing: %v", err)
		}
	}

	return v.reset(ctx,
		meta.UserID,
		meta.Name,
		passwordModel{
			Name:  data.Meta.Name,
			Data:  newData,
			Notes: newNotes,
		})
}

func (v *vault) reset(ctx context.Context, userID string, name []byte, model passwordModel) error {
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
	qb.WriteString("UPDATE passwords SET ")
	if len(model.Name) != 0 {
		fieldOrder++

		qb.WriteString(fmt.Sprintf("name = $%d", fieldOrder))
		args = append(args, model.Name)
	}
	if len(model.Data) != 0 {
		if fieldOrder > 0 {
			qb.WriteString(", ")
		}
		fieldOrder++
		qb.WriteString(fmt.Sprintf("data = $%d", fieldOrder))
		args = append(args, base64.StdEncoding.EncodeToString(model.Data))
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

	qb.WriteString(fmt.Sprintf(" WHERE user_id = $%d AND name = $%d", fieldOrder+1, fieldOrder+2))
	args = append(args, userID, name)

	_, err = tx.Exec(ctx, qb.String(), args...)
	return err
}

// Delete deletes the password pair.
func (v *vault) Delete(ctx context.Context, meta models.ObjectMeta) error {
	const query = `DELETE FROM passwords WHERE user_id = $1 AND name = $2`
	_, err := v.pool.Exec(ctx, query,
		meta.UserID,
		meta.Name,
	)
	return err
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
