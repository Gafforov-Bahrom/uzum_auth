package login_v1

import (
	"context"
	"errors"

	"github.com/Shemistan/uzum_auth/internal/models"
	s "github.com/Shemistan/uzum_auth/internal/storage"
	"github.com/Shemistan/uzum_auth/internal/utils/hasher"
	"github.com/Shemistan/uzum_auth/internal/utils/jwt"
)

type ILoginService interface {
	Login(ctx context.Context, req *models.AuthUser) (*models.Token, error)
	Check(ctx context.Context) error
	GetUserId(ctx context.Context, accessToken string) (uint64, error)
	GetUserRole(ctx context.Context, accessToken string) (*models.GetUserRoleOut, error)
}

type serviceLogin struct {
	TokenSecretKey string
	storage        s.IStorage
}

func NewLoginSystemService(TokenSecretKey string, storage s.IStorage) ILoginService {
	return &serviceLogin{
		TokenSecretKey: TokenSecretKey,
		storage:        storage,
	}
}

func (s *serviceLogin) Login(ctx context.Context, req *models.AuthUser) (*models.Token, error) {
	passwordHashOld, err := s.storage.GetPassword(ctx, req.Login)
	if err != nil {
		return nil, err
	}

	if ok := hasher.CheckPassword(passwordHashOld, req.Password); !ok {
		return nil, errors.New("password is not valid")
	}

	res, err := jwt.GenerateTokens(req.Login, "test", s.TokenSecretKey)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (s *serviceLogin) Check(ctx context.Context) error {
	token, err := jwt.ExtractTokenFromContext(ctx)
	if err != nil {
		return err
	}

	_, err = jwt.ValidateToken(token, s.TokenSecretKey)
	if err != nil {
		return err
	}

	return nil
}

func (s *serviceLogin) GetUserId(ctx context.Context, token string) (uint64, error) {
	claims, err := jwt.ValidateToken(token, s.TokenSecretKey)
	if err != nil {
		return 0, err
	}
	login := claims.Login
	user, err := s.storage.GetUser(ctx, login)
	if err != nil {
		return 0, err
	}

	return user.Id, nil
}

func (s *serviceLogin) GetUserRole(ctx context.Context, token string) (*models.GetUserRoleOut, error) {
	claims, err := jwt.ValidateToken(token, s.TokenSecretKey)
	if err != nil {
		return nil, err
	}
	login := claims.Login
	user, err := s.storage.GetUser(ctx, login)
	if err != nil {
		return nil, err
	}

	return &models.GetUserRoleOut{
		Id:   user.Id,
		Role: user.Role,
	}, nil
}
