package middleware

import (
	"context"
	"net/http"
	"strings"

	config "github.com/fatimahaero/go-banking-auth/config"
)

// Mendefinisikan tipe kunci yang aman untuk context
type contextKey string

const (
	// Kunci yang digunakan untuk context
	userIDKey   contextKey = "id"
	usernameKey contextKey = "username"
)

// AuthMiddleware untuk validasi JWT
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		// Hapus prefix "Bearer " dari token
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

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
