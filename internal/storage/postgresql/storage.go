package postgresql

import (
	"context"

	sq "github.com/Masterminds/squirrel"
	"github.com/jmoiron/sqlx"

	"github.com/Shemistan/uzum_auth/internal/models"
	s "github.com/Shemistan/uzum_auth/internal/storage"
)

const tableName = "users"

type storage struct {
	db *sqlx.DB
}

func NewStorage(db *sqlx.DB) s.IStorage {
	return &storage{db: db}
}

func (s *storage) CreateUser(ctx context.Context, u *models.CreateUser) error {
	q := sq.Insert(tableName).
		Columns(
			"name", "surname", "phone", "login",
			"password_hash", "role", "address", "coordinate_address_x",
			"coordinate_address_y").
		Values(
			u.Name, u.Surname, u.Phone, u.Login,
			u.Password, u.Role, u.Address, u.AddressCoordinate.X,
			u.AddressCoordinate.Y).
		RunWith(s.db).
		PlaceholderFormat(sq.Dollar)

	_, err := q.ExecContext(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (s *storage) MultiCreateUser(ctx context.Context, users []*models.CreateUser) (int64, error) {
	var num int64
	q := sq.Insert(tableName).
		Columns(
			"name", "surname", "phone", "login",
			"password_hash", "role", "address", "coordinate_address_x",
			"coordinate_address_y").
		RunWith(s.db).PlaceholderFormat(sq.Dollar)

	for _, u := range users {
		q = q.Values(u.Name, u.Surname, u.Phone, u.Login,
			u.Password, u.Role, u.Address, u.AddressCoordinate.X,
			u.AddressCoordinate.Y)
		num++
	}

	_, err := q.ExecContext(ctx)
	if err != nil {
		return 0, err
	}

	return num, nil
}

func (s *storage) UpdateUser(ctx context.Context, u *models.User, login string) error {
	q := sq.Update(tableName).SetMap(map[string]interface{}{
		"name":                 u.Name,
		"surname":              u.Surname,
		"phone":                u.Phone,
		"address":              u.Address,
		"coordinate_address_x": u.AddressCoordinate.X,
		"coordinate_address_y": u.AddressCoordinate.Y,
	}).
		Where(sq.Eq{"login": login}).
		RunWith(s.db).
		PlaceholderFormat(sq.Dollar)

	_, err := q.ExecContext(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (s *storage) DeleteUser(ctx context.Context, login string) error {
	q := sq.Delete(tableName).
		Where(sq.Eq{"login": login}).
		RunWith(s.db).
		PlaceholderFormat(sq.Dollar)

	_, err := q.ExecContext(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (s *storage) ChangePassword(ctx context.Context, req *models.AuthUser) error {
	q := sq.Update(tableName).SetMap(map[string]interface{}{
		"password": req.Password,
	}).
		Where(sq.Eq{"login": req.Login}).
		RunWith(s.db).
		PlaceholderFormat(sq.Dollar)

	_, err := q.ExecContext(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (s *storage) GetUser(ctx context.Context, login string) (*models.User, error) {
	var user models.User
	q := sq.Select("id", "name", "surname", "phone",
		"role", "address", "coordinate_address_x",
		"coordinate_address_y").
		From(tableName).
		Where(sq.Eq{"login": login}).
		RunWith(s.db).
		PlaceholderFormat(sq.Dollar)

	err := q.QueryRowContext(ctx).
		Scan(&user.Id, &user.Name, &user.Surname, &user.Phone,
			&user.Role, &user.Address, &user.AddressCoordinate.X,
			&user.AddressCoordinate.Y)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *storage) GetUsers(_ context.Context, _ []string) ([]*models.User, error) {
	return nil, nil
}

func (s *storage) GetAllUsers(_ context.Context) ([]*models.User, error) {
	return nil, nil
}

func (s *storage) GetPassword(ctx context.Context, login string) (string, error) {
	var passwordHash string
	q := sq.Select("password_hash").
		From(tableName).
		Where(sq.Eq{"login": login}).
		RunWith(s.db).
		PlaceholderFormat(sq.Dollar)

	err := q.QueryRowContext(ctx).
		Scan(&passwordHash)

	if err != nil {
		return "", err
	}

	return passwordHash, nil
}
