package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	Username       string     `json:"username" db:"username"`
	Password       string     `json:"-" db:"password_hash"`
	Email          string     `json:"email" db:"email"`
	TOTPEnabled    bool       `json:"totp_enabled" db:"totp_enabled"`
	TOTPSecret     string     `json:"-" db:"totp_secret"`
	FailedAttempts int        `json:"-" db:"failed_attempts"`
	LastFailedAt   *time.Time `json:"-" db:"last_failed_at"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Email    string `json:"email" binding:"required"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type TOTPVerifyRequest struct {
	Username string `json:"username" binding:"required"`
	Code     string `json:"code" binding:"required,len=6"`
}

type LoginResponse struct {
	RequiresTOTP bool   `json:"requires_totp"`
	Token        string `json:"token,omitempty"`
	Message      string `json:"message,omitempty"`
}

type TOTPSetupResponse struct {
	Secret     string `json:"secret"`
	QRCodeURL  string `json:"qr_code_url"`
	ManualCode string `json:"manual_code"`
}

type ErrorResponse struct {
	Error             string `json:"error"`
	RemainingAttempts int    `json:"remaining_attempts,omitempty"`
	BlockedUntil      string `json:"blocked_until,omitempty"`
}
