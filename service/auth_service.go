package service

import (
	"fmt"

	adapter "github.com/fatimahaero/go-banking-auth/adapter/repository"

	config "github.com/fatimahaero/go-banking-auth/config"

	"github.com/fatimahaero/go-banking-auth/domain"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	LoginAccount(username, password string) (string, error)
	GetAccountByUsername(username string) (*domain.Account, error)
}

type AuthAdapterDB struct {
	repo adapter.AuthRepository
}

var _ AuthService = (*AuthAdapterDB)(nil)

func NewAuthService(repo adapter.AuthRepository) AuthService {
	return &AuthAdapterDB{repo: repo}
}
func (s *AuthAdapterDB) GetAccountByUsername(username string) (*domain.Account, error) {
	return s.repo.GetAccountByUsername(username)
}

func (u *AuthAdapterDB) LoginAccount(username, password string) (string, error) {
	user, err := u.repo.GetAccountByUsername(username)
	if err != nil {
		return "", err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", fmt.Errorf("invalid password: %v", err)
	}

	token, err := config.GenerateJWT(user.ID, user.Username)
	if err != nil {
		return "", fmt.Errorf("could not generate token: %v", err)
	}

	err = u.repo.SaveToken(user.ID, token)
	if err != nil {
		return "", fmt.Errorf("could not save token: %v", err)
	}

	return token, nil
}
