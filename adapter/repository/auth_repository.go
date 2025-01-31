package adapter

import (
	"fmt"

	"github.com/fatimahaero/go-banking-auth/domain"
	"github.com/jmoiron/sqlx"
)

type AuthRepository interface {
	GetAccountByUsername(username string) (*domain.Account, error)
	SaveToken(accountID string, token string) error
}

type AuthRepositoryDB struct {
	DB *sqlx.DB
}

func NewAuthRepositoryDB(db *sqlx.DB) *AuthRepositoryDB {
	return &AuthRepositoryDB{DB: db}
}

func (a *AuthRepositoryDB) GetAccountByUsername(username string) (*domain.Account, error) {
	var account domain.Account
	query := "SELECT id, customer_id, username, password, balance, currency, status FROM accounts WHERE username = ?"
	err := a.DB.Get(&account, query, username)
	if err != nil {
		if account == (domain.Account{}) {
			return nil, fmt.Errorf("no accounts found")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	return &account, nil
}

func (a *AuthRepositoryDB) SaveToken(accountID string, token string) error {
	query := "INSERT INTO refresh_token_store (account_id, refresh_token) VALUES (?, ?)"
	_, err := a.DB.Exec(query, accountID, token)
	if err != nil {
		return fmt.Errorf("could not save token: %v", err)
	}

	return nil
}
