package config

import (
	"github.com/fatimahaero/go-banking-auth/domain"

	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"
)

/*
 * Implemtasi database dengan config dari .yaml
 */
func NewDBConnectionYAML() (*sqlx.DB, error) {
	config, err := domain.GetConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get config")
	}

	db, err := sqlx.Connect("mysql", config.GetDatabaseConfig())
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect database")
	} else {
		log.Info().Msg("Database connected")
	}

	return db, nil
}

/*
 * Use database config from .env
 */
func NewDBConnectionENV() (*sqlx.DB, error) {
	config, err := domain.GetConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get config")
	}

	db, err := sqlx.Connect("mysql", config.GetDatabaseENVConfig())
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect database")
	} else {
		log.Info().Msg("Database connected")
	}

	return db, nil
}
