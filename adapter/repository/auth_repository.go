package adapter

import (
	"database/sql"
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
	var existingToken string
	querySelect := "SELECT refresh_token FROM refresh_token_store WHERE account_id = ?"

	// Cek apakah refresh_token sudah ada
	err := a.DB.Get(&existingToken, querySelect, accountID)
	if err != nil {
		if err == sql.ErrNoRows {
			// Jika tidak ada, lakukan INSERT
			queryInsert := "INSERT INTO refresh_token_store (account_id, refresh_token) VALUES (?, ?)"
			_, err = a.DB.Exec(queryInsert, accountID, token)
			if err != nil {
				return fmt.Errorf("failed to insert refresh token: %v", err)
			}
		} else {
			// Jika ada error lain selain data tidak ditemukan
			return fmt.Errorf("database error: %v", err)
		}
	} else {
		// Jika refresh_token sudah ada, lakukan UPDATE
		queryUpdate := "UPDATE refresh_token_store SET refresh_token = ? WHERE account_id = ?"
		_, err = a.DB.Exec(queryUpdate, token, accountID)
		if err != nil {
			return fmt.Errorf("failed to update refresh token: %v", err)
		}
	}

	return nil
}
