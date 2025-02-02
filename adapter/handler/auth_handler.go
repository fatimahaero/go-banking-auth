package adapter

import (
	"encoding/json"
	"net/http"

	"github.com/fatimahaero/go-banking-auth/dto"
	"github.com/fatimahaero/go-banking-auth/service"
	"github.com/fatimahaero/go-banking-auth/utils"

	config "github.com/fatimahaero/go-banking-auth/config"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog/log"
)

type AuthHandlerDB struct {
	Service   service.AuthService
	Validator validator.Validate
}

func NewAuthHandlerDB(service service.AuthService) *AuthHandlerDB {
	return &AuthHandlerDB{Service: service, Validator: *validator.New()}
}

func (h *AuthHandlerDB) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.ErrorResponse(w, http.StatusMethodNotAllowed, "error", "Method not allowed")
		return
	}

	log.Info().
		Str("method", r.Method).
		Str("path", r.URL.Path).
		Msg("Login")

	var req dto.LoginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		utils.ErrorResponse(w, http.StatusBadRequest, "error", "Invalid request body")
		return
	}

	if err := h.Validator.Struct(req); err != nil {
		errorMessage := utils.CustomValidationError(err)
		utils.ErrorResponse(w, http.StatusUnprocessableEntity, "error", errorMessage)
		return
	}

	accessToken, refreshToken, err := h.Service.LoginAccount(req.Username, req.Password)
	if err != nil {
		log.Error().Err(err).Msg("Username or password is incorrect. Failed to login")
		utils.ErrorResponse(w, http.StatusUnauthorized, "error", err.Error())
		return
	}

	resp := dto.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	utils.ResponseJSON(w, resp, http.StatusOK, "success", "Login successful")
	log.Info().Str("username", req.Username).Msg("Login successful")
}

func (h *AuthHandlerDB) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req dto.RefreshTokenRequest

	json.NewDecoder(r.Body).Decode(&req)

	// Parse refresh token
	claims, err := config.ParseToken(req.RefreshToken)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Ambil refresh token dari database
	storedToken, err := h.Service.RefreshToken(req.RefreshToken)
	if err != nil || storedToken != req.RefreshToken {
		http.Error(w, "Refresh token mismatch", http.StatusUnauthorized)
		return
	}

	// Generate access token baru
	newAccessToken, err := config.GenerateJWT(claims.ID, claims.Username, 15)
	if err != nil {
		http.Error(w, "Could not generate new access token", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"access_token": newAccessToken,
	}

	json.NewEncoder(w).Encode(response)
}
