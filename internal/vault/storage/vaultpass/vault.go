package vaultpass

import (
	"context"
	"errors"
	"fmt"
	"strings"

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

func (v *vault) Save(ctx context.Context, pass models.Password) error {
	name, err := v.enc.Encrypt(pass.Name)
	if err != nil {
		return fmt.Errorf("can't prepare name for storing: %v", err)
	}
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
		UserID: pass.UserID,
		Name:   name,
		Data:   data,
		Notes:  notes,
	})
	return err
}

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
		model.Data,
		model.Notes,
	)
	return err
}

func (v *vault) GetByName(ctx context.Context, userID, recordName string) (models.Password, error) {
	targetName, err := v.enc.Encrypt([]byte(recordName))
	if err != nil {
		return models.Password{}, fmt.Errorf("can't process record name: %v", err)
	}
	model, err := v.getByName(ctx, userID, string(targetName))
	if err != nil {
		return models.Password{}, err
	}

	name, err := v.enc.Decrypt(model.Name)
	if err != nil {
		return models.Password{}, err
	}
	data, err := v.enc.Decrypt(model.Data)
	if err != nil {
		return models.Password{}, err
	}
	var notes []byte
	if len(model.Notes) > 0 {
		notes, err = v.enc.Decrypt(model.Notes)
		if err != nil {
			return models.Password{}, err
		}
	}

	return models.Password{
		UserID: model.UserID,
		Name:   name,
		Data:   data,
		Notes:  notes,
	}, nil
}

func (v *vault) getByName(ctx context.Context, userID, name string) (passwordModel, error) {
	const query = `SELECT * FROM passwords WHERE user_id = $1 AND name = $2`
	row := v.pool.QueryRow(ctx, query,
		userID,
		name,
	)

	var m passwordModel
	err := row.Scan(&m.ID, &m.UserID, &m.Name, &m.Data, &m.Notes)
	if err != nil {
		return passwordModel{}, err
	}
	return m, nil
}

func (v *vault) Index(ctx context.Context, userID string) ([]models.Password, error) {
	records, err := v.index(ctx, userID)
	if err != nil {
		return nil, err
	}

	passwords := make([]models.Password, len(records))
	for i, r := range records {
		name, err := v.enc.Decrypt([]byte(r.Name))
		if err != nil {
			return nil, err
		}

		passwords[i] = models.Password{
			Name: name,
		}
	}
	return passwords, nil
}

func (v *vault) index(ctx context.Context, userID string) ([]passwordModel, error) {
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

	records := make([]passwordModel, 0)
	for rows.Next() {
		var m passwordModel
		if err = rows.Scan(&m.Name); err != nil {
			return nil, err
		}
		records = append(records, m)
	}
	if rows.Err() != nil {
		return nil, err
	}
	return records, err
}

func (v *vault) Reset(ctx context.Context, userID string, name string, pass models.Password) error {
	if len(pass.Name) == 0 && len(pass.Data) == 0 && len(pass.Notes) == 0 {
		return fmt.Errorf("nothing to update")
	}

	recordName, err := v.enc.Encrypt([]byte(name))
	if err != nil {
		return fmt.Errorf("can't prepare record name: %v", err)
	}
	var newName []byte
	if len(pass.Name) != 0 {
		newName, err = v.enc.Encrypt(pass.Name)
		if err != nil {
			return fmt.Errorf("can't prepare new name for storing: %v", err)
		}
	}
	var newData []byte
	if len(pass.Data) != 0 {
		newData, err = v.enc.Encrypt(pass.Data)
		if err != nil {
			return fmt.Errorf("can't prepare new data for storing: %v", err)
		}
	}
	var newNotes []byte
	if len(pass.Notes) != 0 {
		newNotes, err = v.enc.Encrypt(pass.Notes)
		if err != nil {
			return fmt.Errorf("can't prepare new notes for storing: %v", err)
		}
	}

	return v.reset(ctx, userID, string(recordName), passwordModel{
		Name:  newName,
		Data:  newData,
		Notes: newNotes,
	})
}

func (v *vault) reset(ctx context.Context, userID string, name string, model passwordModel) error {
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
	qb.WriteString("UPDATE passwords")
	if len(model.Name) != 0 {
		qb.WriteString(" SET name = $1")
	}
	if len(model.Data) != 0 {
		qb.WriteString(" SET data = $2")
	}
	if len(model.Notes) != 0 {
		qb.WriteString(" SET notes = $3")
	}
	qb.WriteString(" WHERE user_id = $4")

	_, err = tx.Exec(ctx, qb.String(),
		model.Name,
		model.Data,
		model.Notes,
		userID,
	)
	return err
}

func (v *vault) Delete(ctx context.Context, userID string, name string) error {
	recordName, err := v.enc.Encrypt([]byte(name))
	if err != nil {
		return fmt.Errorf("can't process a record name: %v", err)
	}

	const query = `DELETE passwords WHERE user_id = $1 AND name = $2`
	_, err = v.pool.Exec(ctx, query,
		userID,
		recordName,
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
