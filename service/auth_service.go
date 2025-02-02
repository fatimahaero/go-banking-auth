package service

import (
	"fmt"

	adapter "github.com/fatimahaero/go-banking-auth/adapter/repository"

	config "github.com/fatimahaero/go-banking-auth/config"

	"github.com/fatimahaero/go-banking-auth/domain"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	LoginAccount(username, password string) (string, string, error)
	GetAccountByUsername(username string) (*domain.Account, error)
	RefreshToken(refreshToken string) (string, error)
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

func (u *AuthAdapterDB) LoginAccount(username, password string) (string, string, error) {
	user, err := u.repo.GetAccountByUsername(username)
	if err != nil {
		return "", "", err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", "", fmt.Errorf("invalid password: %v", err)
	}

	accessToken, err := config.GenerateJWT(user.ID, user.Username, 15) // Berlaku 15 menit
	if err != nil {
		return "", "", fmt.Errorf("could not generate token: %v", err)
	}

	refreshToken, err := config.GenerateJWT(user.ID, user.Username, 24*60) // Berlaku 24 jam
	if err != nil {
		return "", "", fmt.Errorf("could not generate refresh token: %v", err)
	}

	err = u.repo.SaveRefreshToken(user.ID, refreshToken)
	if err != nil {
		return "", "", fmt.Errorf("could not save token: %v", err)
	}

	return accessToken, refreshToken, nil
}

func (u *AuthAdapterDB) RefreshToken(refreshToken string) (string, error) {
	// Parse refresh token
	claims, err := config.ParseToken(refreshToken)
	if err != nil {
		fmt.Println("Token parsing failed:", err)
		return "", fmt.Errorf("invalid refresh token: %v", err)
	}

	// Ambil refresh token dari database
	storedToken, err := u.repo.GetRefreshToken(claims.ID)
	if err != nil || storedToken != refreshToken {
		fmt.Println("Refresh token mismatch!")
		return "", fmt.Errorf("refresh token mismatch")
	}
	return storedToken, nil
}
