package vaultcard

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

func (v *vault) Save(ctx context.Context, card models.CreditCard) error {
	data, err := v.enc.Encrypt(card.Data)
	if err != nil {
		return fmt.Errorf("can't prepare data for storing: %v", err)
	}
	var notes []byte
	if len(card.Notes) != 0 {
		b, err := v.enc.Encrypt(card.Notes)
		if err != nil {
			return fmt.Errorf("can't prepare notes for storing: %v", err)
		}
		notes = b
	}

	err = v.save(ctx, creditCardModel{
		UserID: card.Meta.UserID,
		Name:   card.Meta.Name,
		Data:   data,
		Notes:  notes,
	})
	return err
}

type creditCardModel struct {
	ID     string
	UserID string
	Name   []byte
	Data   []byte
	Notes  []byte
}

func (v *vault) save(ctx context.Context, model creditCardModel) error {
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

	const query = `INSERT INTO credit_cards(id, user_id, name, data, notes)
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

func (v *vault) Get(ctx context.Context, meta models.ObjectMeta) (models.CreditCard, error) {
	model, err := v.get(ctx, meta.UserID, meta.Name)
	if err != nil {
		return models.CreditCard{}, err
	}

	data, err := v.enc.Decrypt(model.Data)
	if err != nil {
		return models.CreditCard{}, err
	}
	var notes []byte
	if len(model.Notes) != 0 {
		notes, err = v.enc.Decrypt(model.Notes)
		if err != nil {
			return models.CreditCard{}, err
		}
	}

	return models.CreditCard{
		Meta:  meta,
		Data:  data,
		Notes: notes,
	}, nil
}

func (v *vault) get(ctx context.Context, userID string, recordName []byte) (creditCardModel, error) {
	const query = `SELECT * FROM credit_cards WHERE user_id = $1 AND name = $2`
	row := v.pool.QueryRow(ctx, query, userID, recordName)

	var m creditCardModel
	err := row.Scan(&m.ID, &m.UserID, &m.Name, &m.Data, &m.Notes)
	if err != nil {
		return creditCardModel{}, err
	}

	data, err := decodeBase64(m.Data)
	if err != nil {
		return creditCardModel{}, err
	}
	m.Data = data

	var notes []byte
	if len(m.Notes) != 0 {
		notes, err = decodeBase64(m.Notes)
		if err != nil {
			return creditCardModel{}, err
		}
	}
	m.Notes = notes

	return m, nil
}

func (v *vault) Index(ctx context.Context, userID string) ([]models.CreditCard, error) {
	names, err := v.listNames(ctx, userID)
	if err != nil {
		return nil, err
	}

	cards := make([]models.CreditCard, len(names))
	for i, n := range names {
		cards[i] = models.CreditCard{
			Meta: models.ObjectMeta{
				Name: n,
			},
		}
	}
	return cards, nil
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

	const query = `SELECT name FROM credit_cards WHERE user_id = $1`
	rows, err := tx.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	names := make([][]byte, 0)
	for rows.Next() {
		var m creditCardModel
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

func (v *vault) Update(ctx context.Context, meta models.ObjectMeta, data models.CreditCard) error {
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

	return v.update(ctx,
		meta.UserID,
		meta.Name,
		creditCardModel{
			Name:  data.Meta.Name,
			Data:  newData,
			Notes: newNotes,
		})
}

func (v *vault) update(ctx context.Context, userID string, name []byte, model creditCardModel) error {
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
	qb.WriteString("UPDATE credit_cards SET ")
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

func (v *vault) Delete(ctx context.Context, meta models.ObjectMeta) error {
	const query = `DELETE FROM credit_cards WHERE user_id = $1 AND name = $2`
	_, err := v.pool.Exec(ctx, query, meta.UserID, meta.Name)
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
