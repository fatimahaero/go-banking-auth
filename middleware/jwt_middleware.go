package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/fatimahaero/go-banking-auth/config"
)

// Context keys untuk menyimpan user ID dan username
type contextKey string

const userIDKey contextKey = "userID"
const usernameKey contextKey = "username"

// AuthMiddleware untuk validasi JWT access token
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		// Hapus prefix "Bearer "
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		// Parse access token
		claims, err := config.ParseToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid access token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Set data user di context
		ctx := context.WithValue(r.Context(), userIDKey, claims.ID)
		ctx = context.WithValue(ctx, usernameKey, claims.Username)

		// Lanjutkan request dengan context yang diperbarui
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
