package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"time"

	"authentication-service/internal/models"
	"authentication-service/internal/repository"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidTOTP        = errors.New("invalid TOTP code")
	ErrTOTPRequired       = errors.New("TOTP verification required")
	ErrUserBlocked        = errors.New("user is temporarily blocked")
)

type AuthService struct {
	userRepo      *repository.UserRepository
	jwtSecret     []byte
	encryptionKey []byte
	maxAttempts   int
	blockDuration time.Duration
}

func NewAuthService(
	userRepo *repository.UserRepository,
	jwtSecret string,
	encryptionKey string,
	maxAttempts int,
	blockDuration time.Duration,
) *AuthService {
	return &AuthService{
		userRepo:      userRepo,
		jwtSecret:     []byte(jwtSecret),
		encryptionKey: []byte(encryptionKey),
		maxAttempts:   maxAttempts,
		blockDuration: blockDuration,
	}
}

func (s *AuthService) Register(username, password, email string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user := &models.User{
		Username:    username,
		Password:    string(hashedPassword),
		Email:       email,
		TOTPEnabled: false,
		TOTPSecret:  "",
	}

	return s.userRepo.Create(user)
}

func (s *AuthService) Login(username, password string) (*models.LoginResponse, error) {
	user, err := s.userRepo.GetByUsername(username)
	if err != nil {
		if err == repository.ErrUserNotFound {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	// Проверка блокировки
	if user.FailedAttempts >= s.maxAttempts {
		if user.LastFailedAt != nil && time.Since(*user.LastFailedAt) < s.blockDuration {
			return nil, ErrUserBlocked
		}
		// Сброс счетчика после истечения времени блокировки
		if err := s.userRepo.ResetFailedAttempts(user.ID); err != nil {
			return nil, err
		}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		attempts := user.FailedAttempts + 1
		if err := s.userRepo.UpdateFailedAttempts(user.ID, attempts); err != nil {
			return nil, err
		}
		return nil, ErrInvalidCredentials
	}

	// Сброс счетчика после успешного входа
	if err := s.userRepo.ResetFailedAttempts(user.ID); err != nil {
		return nil, err
	}

	if user.TOTPEnabled {
		return &models.LoginResponse{
			RequiresTOTP: true,
			Message:      "TOTP verification required",
		}, nil
	}

	token, err := s.generateJWT(user)
	if err != nil {
		return nil, err
	}

	return &models.LoginResponse{
		RequiresTOTP: false,
		Token:        token,
	}, nil
}

func (s *AuthService) VerifyTOTP(username, code string) (*models.LoginResponse, error) {
	user, err := s.userRepo.GetByUsername(username)
	if err != nil {
		return nil, err
	}

	if !user.TOTPEnabled {
		return nil, errors.New("TOTP not enabled for this user")
	}

	decryptedSecret, err := s.decryptTOTPSecret(user.TOTPSecret)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	valid := false

	for i := -2; i <= 2; i++ {
		t := now.Add(time.Duration(i*30) * time.Second)
		expectedCode, _ := totp.GenerateCode(decryptedSecret, t)

		if code == expectedCode {
			valid = true
			break
		}
	}

	if !valid {
		attempts := user.FailedAttempts + 1
		if err := s.userRepo.UpdateFailedAttempts(user.ID, attempts); err != nil {
			return nil, err
		}
		return nil, ErrInvalidTOTP
	}

	if err := s.userRepo.ResetFailedAttempts(user.ID); err != nil {
		return nil, err
	}

	token, err := s.generateJWT(user)
	if err != nil {
		return nil, err
	}

	return &models.LoginResponse{
		RequiresTOTP: false,
		Token:        token,
	}, nil
}

func (s *AuthService) SetupTOTP(userID string) (*models.TOTPSetupResponse, error) {
	log.Printf("Setting up TOTP for user ID: %s", userID)

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "auth-service",
		AccountName: userID,
		Period:      30,
		Digits:      6,
	})
	if err != nil {
		log.Printf("Error generating TOTP: %v", err)
		return nil, err
	}

	log.Printf("Generated TOTP key: %+v", key)
	log.Printf("Secret: %s", key.Secret())
	log.Printf("URL: %s", key.URL())

	// Генерируем QR-код
	qrBytes, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		log.Printf("Error generating QR code: %v", err)
		return nil, err
	}

	// Конвертируем в base64
	qrBase64 := base64.StdEncoding.EncodeToString(qrBytes)
	qrCodeURL := "data:image/png;base64," + qrBase64

	log.Printf("Generated QR code (first 100 chars): %s...", qrCodeURL[:100])

	encryptedSecret, err := s.encryptTOTPSecret(key.Secret())
	if err != nil {
		log.Printf("Error encrypting TOTP secret: %v", err)
		return nil, err
	}

	if err := s.userRepo.UpdateTOTPSecret(uuid.MustParse(userID), encryptedSecret, true); err != nil {
		log.Printf("Error updating TOTP secret in database: %v", err)
		return nil, err
	}

	log.Printf("TOTP setup completed successfully for user ID: %s", userID)
	return &models.TOTPSetupResponse{
		Secret:     key.Secret(),
		QRCodeURL:  qrCodeURL,
		ManualCode: key.Secret(),
	}, nil
}

func (s *AuthService) DisableTOTP(userID string) error {
	return s.userRepo.UpdateTOTPSecret(uuid.MustParse(userID), "", false)
}

func (s *AuthService) GetUserByUsername(username string) (*models.User, error) {
	return s.userRepo.GetByUsername(username)
}

func (s *AuthService) generateJWT(user *models.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":      user.ID.String(),
		"username": user.Username,
		"email":    user.Email,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	})

	return token.SignedString(s.jwtSecret)
}

func (s *AuthService) encryptTOTPSecret(secret string) (string, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(secret), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (s *AuthService) decryptTOTPSecret(encryptedSecret string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedSecret)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
