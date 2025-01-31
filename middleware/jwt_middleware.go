package middleware

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	"github.com/fatimahaero/go-banking-auth/config"
	"github.com/jmoiron/sqlx"
)

// Mendefinisikan tipe kunci yang aman untuk context
type contextKey string

const (
	// Kunci yang digunakan untuk context
	userIDKey   contextKey = "id"
	usernameKey contextKey = "username"
)

// AuthMiddleware untuk validasi JWT
func AuthMiddleware(next http.Handler, db *sqlx.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		// Hapus prefix "Bearer " dari token
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		// Periksa apakah token ada dalam database
		var accountID string
		query := "SELECT account_id FROM refresh_token_store WHERE refresh_token = ?"

		err := db.Get(&accountID, query, tokenString)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
			} else {
				http.Error(w, fmt.Sprintf("Database error: %v", err), http.StatusInternalServerError)
			}
			return
		}

		claims, err := config.ParseToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Ambil context dari request dan set data claims ke dalam context
		ctx := r.Context()
		ctx = context.WithValue(ctx, userIDKey, claims.ID)
		ctx = context.WithValue(ctx, usernameKey, claims.Username)

		// Lanjutkan dengan context yang sudah diperbarui
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
