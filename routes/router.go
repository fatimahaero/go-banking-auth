package routes

import (
	"fmt"

	hand "github.com/fatimahaero/go-banking-auth/adapter/handler"
	repo "github.com/fatimahaero/go-banking-auth/adapter/repository"
	conf "github.com/fatimahaero/go-banking-auth/config"
	"github.com/fatimahaero/go-banking-auth/domain"
	serv "github.com/fatimahaero/go-banking-auth/service"

	"github.com/fatimahaero/go-banking-auth/middleware"
	"github.com/fatimahaero/go-banking-lib/logger"

	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"
)

func NewRouter(router *mux.Router, db *sqlx.DB) {
	// apply middleware to all routes
	router.Use(middleware.ApiKeyMiddleware)
	authRepo := repo.NewAuthRepositoryDB(db)
	authService := serv.NewAuthService(authRepo)
	authHandler := hand.NewAuthHandlerDB(authService)

	router.Handle("/login", http.HandlerFunc(authHandler.Login)).Methods("POST")
	router.Handle("/refresh-token", http.HandlerFunc(authHandler.RefreshToken)).Methods("POST")
}

func StartServer() {

	// Start of log setup
	logger.InitiateLog()
	defer logger.CloseLog() // Close log when application is stopped
	// End of log setup

	config, err := domain.GetConfig()
	if err != nil {
		log.Error().Err(err).Msg("Failed to load config:")
		panic(err) // Hentikan program jika gagal mendapatkan config
	}
	port := config.Server.Port

	db, _ := conf.NewDBConnectionENV()

	defer db.Close()

	router := mux.NewRouter()

	NewRouter(router, db)

	fmt.Println("starting server on port " + port)

	http.ListenAndServe(":"+port, router)
}
