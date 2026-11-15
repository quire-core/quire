package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"github.com/quire-core/quire/internal/api/models"
	"github.com/quire-core/quire/internal/config"
)

const (
	maxUsernameChars  = 20
	maxPasswordBytes  = 72 // bcrypt only considers the first 72 bytes
	refreshTokenBytes = 32 // bytes of entropy, equivalent to 256 bits
)

// validateRegisterReq returns an error code when req is invalid, or an empty
// string when it is valid.
func validateRegisterReq(req models.RegisterReq) string {
	return validateCredentials(req.Username, req.Password)
}

// validateLoginReq returns an error code when req is invalid, or an empty
// string when it is valid.
func validateLoginReq(req models.LoginRequest) string {
	return validateCredentials(req.Username, req.Password)
}

// validateCredentials returns an error code when username or password violates
// the shared credential rules, or an empty string when both are valid.
func validateCredentials(username, password string) string {
	if strings.TrimSpace(username) == "" {
		return "username_required"
	}

	if utf8.RuneCountInString(username) > maxUsernameChars {
		return "username_too_long"
	}

	if password == "" {
		return "password_required"
	}

	if len(password) > maxPasswordBytes {
		return "password_too_long"
	}

	return ""
}

// generateRefreshToken returns a URL-safe random refresh token with 256 bits of
// entropy.
func generateRefreshToken() (string, error) {
	random := make([]byte, refreshTokenBytes)

	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(random), nil
}

// hashRefreshToken returns the SHA-256 hash of token as a lowercase hex string.
func hashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))

	return hex.EncodeToString(sum[:])
}

// errJWTSecretMissing indicates that JWT_SECRET is not configured.
var errJWTSecretMissing = errors.New("jwt secret is missing")

// generateAccessToken returns a signed JWT for the given user.
func generateAccessToken(userID int64, username string) (string, error) {
	secret := config.GetJWTSecret()
	if secret == "" {
		return "", errJWTSecretMissing
	}

	now := time.Now()

	claims := models.Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenTTL)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}

	return signedToken, nil
}
