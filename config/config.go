package config

import (
	"fmt"
	"os"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	Security SecurityConfig
	TLS      TLSConfig
}

type ServerConfig struct {
	Host string
	Port string
}

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

type JWTConfig struct {
	SecretKey  string
	Expiration time.Duration
}

type SecurityConfig struct {
	EncryptionKey    string
	RateLimitWindow  time.Duration
	MaxLoginAttempts int
}

type TLSConfig struct {
	CertPath string
	KeyPath  string
}

func LoadConfig() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		return nil, fmt.Errorf("error loading .env file: %w", err)
	}

	rateLimitWindow, err := time.ParseDuration(os.Getenv("RATE_LIMIT_WINDOW"))
	if err != nil {
		rateLimitWindow = 5 * time.Minute // default value
	}

	jwtExpiration, err := time.ParseDuration(os.Getenv("JWT_EXPIRATION"))
	if err != nil {
		jwtExpiration = 24 * time.Hour // default value
	}

	return &Config{
		Server: ServerConfig{
			Host: os.Getenv("SERVER_HOST"),
			Port: os.Getenv("SERVER_PORT"),
		},
		Database: DatabaseConfig{
			Host:     os.Getenv("DB_HOST"),
			Port:     os.Getenv("DB_PORT"),
			User:     os.Getenv("DB_USER"),
			Password: os.Getenv("DB_PASSWORD"),
			DBName:   os.Getenv("DB_NAME"),
			SSLMode:  os.Getenv("DB_SSL_MODE"),
		},
		JWT: JWTConfig{
			SecretKey:  os.Getenv("JWT_SECRET_KEY"),
			Expiration: jwtExpiration,
		},
		Security: SecurityConfig{
			EncryptionKey:    os.Getenv("ENCRYPTION_KEY"),
			RateLimitWindow:  rateLimitWindow,
			MaxLoginAttempts: 5,
		},
		TLS: TLSConfig{
			CertPath: os.Getenv("TLS_CERT_PATH"),
			KeyPath:  os.Getenv("TLS_KEY_PATH"),
		},
	}, nil
}

func (c *DatabaseConfig) GetDSN() string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.DBName, c.SSLMode)
}
