package users

import (
	"context"
	"errors"
	"fmt"

	"github.com/alukart32/yandex/practicum/passkee/internal/vault/models"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type usersStorage struct {
	pool *pgxpool.Pool
}

func (s *usersStorage) Save(ctx context.Context, user models.User) error {
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

	const query = `INSERT INTO users(username, password, id) VALUES($1, $2, $3)`

	_, err = tx.Exec(ctx, query,
		user.Username,
		string(user.Password),
		user.ID,
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

func (s *usersStorage) Get(ctx context.Context, username string) (models.User, error) {
	const query = `SELECT * FROM users WHERE username = %1`
	var user models.User
	row := s.pool.QueryRow(ctx, query, username)
	err := row.Scan(
		&user.ID,
		&user.Username,
		&user.Password,
	)
	if err != nil && errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}

	return user, err
}

// finishTx rollbacks transaction if error is provided.
// If err is nil transaction is committed.
func (s *usersStorage) finishTx(ctx context.Context, tx pgx.Tx, err error) error {
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
