package repository

import (
	"database/sql"
	"errors"
	"time"

	"authentication-service/internal/models"

	"github.com/google/uuid"
)

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrUserExists      = errors.New("user already exists")
	ErrInvalidPassword = errors.New("invalid password")
	ErrTooManyAttempts = errors.New("too many failed attempts")
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(user *models.User) error {
	// Проверяем, существует ли пользователь с таким username
	existingUser, err := r.GetByUsername(user.Username)
	if err != nil && err != ErrUserNotFound {
		return err
	}
	if existingUser != nil {
		return ErrUserExists
	}

	// Проверяем, существует ли пользователь с таким email
	query := `SELECT id FROM users WHERE email = $1`
	var id uuid.UUID
	err = r.db.QueryRow(query, user.Email).Scan(&id)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == nil {
		return ErrUserExists
	}

	query = `
		INSERT INTO users (id, username, password_hash, email, totp_enabled, totp_secret, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id`

	user.ID = uuid.New()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	err = r.db.QueryRow(
		query,
		user.ID,
		user.Username,
		user.Password,
		user.Email,
		user.TOTPEnabled,
		user.TOTPSecret,
		user.CreatedAt,
		user.UpdatedAt,
	).Scan(&user.ID)

	if err != nil {
		return err
	}

	return nil
}

func (r *UserRepository) GetByUsername(username string) (*models.User, error) {
	query := `
		SELECT id, username, password_hash, email, totp_enabled, totp_secret, 
			   failed_attempts, last_failed_at, created_at, updated_at
		FROM users 
		WHERE username = $1
	`
	user := &models.User{}
	err := r.db.QueryRow(query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Password,
		&user.Email,
		&user.TOTPEnabled,
		&user.TOTPSecret,
		&user.FailedAttempts,
		&user.LastFailedAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) UpdateTOTPSecret(userID uuid.UUID, secret string, enabled bool) error {
	query := `
		UPDATE users
		SET totp_secret = $1, totp_enabled = $2, updated_at = NOW()
		WHERE id = $3`

	result, err := r.db.Exec(query, secret, enabled, userID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}

func (r *UserRepository) UpdateFailedAttempts(userID uuid.UUID, attempts int) error {
	query := `
		UPDATE users
		SET failed_attempts = $1, last_failed_at = NOW(), updated_at = NOW()
		WHERE id = $2`

	result, err := r.db.Exec(query, attempts, userID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}

func (r *UserRepository) ResetFailedAttempts(userID uuid.UUID) error {
	query := `
		UPDATE users
		SET failed_attempts = 0, last_failed_at = NULL, updated_at = NOW()
		WHERE id = $1`

	result, err := r.db.Exec(query, userID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}
