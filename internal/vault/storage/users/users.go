package users

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/alukart32/yandex/practicum/passkee/internal/vault/models"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Storage struct {
	pool *pgxpool.Pool
}

func NewStorage(pool *pgxpool.Pool) (*Storage, error) {
	if pool == nil {
		return nil, fmt.Errorf("nil postgres pool")
	}

	return &Storage{
		pool: pool,
	}, nil
}

func (s *Storage) Save(ctx context.Context, user models.User) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:       pgx.RepeatableRead,
		AccessMode:     pgx.ReadWrite,
		DeferrableMode: pgx.NotDeferrable,
	})
	if err != nil {
		return fmt.Errorf("can't start transaction: %v", err.Error())
	}
	defer func() {
		err = s.finishTx(ctx, tx, err)
	}()

	const query = `INSERT INTO users(id, username, password) VALUES($1, $2, $3)`

	_, err = tx.Exec(ctx, query,
		user.ID,
		base64.StdEncoding.EncodeToString(user.Username),
		base64.StdEncoding.EncodeToString(user.Password),
	)

	var pgErr *pgconn.PgError
	if err != nil && errors.As(err, &pgErr) {
		if pgerrcode.IsIntegrityConstraintViolation(pgErr.SQLState()) &&
			pgErr.SQLState() == pgerrcode.UniqueViolation {
			err = fmt.Errorf("username unique violation")
		}
	}
	return err
}

func (s *Storage) Get(ctx context.Context, username string) (models.User, error) {
	const query = `SELECT * FROM users WHERE username = $1`
	var (
		recordID       string
		recordUsername []byte
		recordPassword []byte
	)
	row := s.pool.QueryRow(ctx, query, base64.StdEncoding.EncodeToString([]byte(username)))
	err := row.Scan(
		&recordID,
		&recordUsername,
		&recordPassword,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = nil
		}
		return models.User{}, err
	}

	usernameBase64, err := decodeBase64(recordUsername)
	if err != nil {
		return models.User{}, fmt.Errorf("can't read data: %v", err)
	}

	passwordBase64, err := decodeBase64(recordPassword)
	if err != nil {
		return models.User{}, fmt.Errorf("can't read data: %v", err)
	}
	user := models.User{
		ID:       recordID,
		Username: usernameBase64,
		Password: passwordBase64,
	}

	return user, nil
}

// finishTx rollbacks transaction if error is provided.
// If err is nil transaction is committed.
func (s *Storage) finishTx(ctx context.Context, tx pgx.Tx, err error) error {
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
	textBase64 := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
	n, err := base64.StdEncoding.Decode(textBase64, src)
	if err != nil {
		return nil, err
	}
	return textBase64[:n], nil
}
