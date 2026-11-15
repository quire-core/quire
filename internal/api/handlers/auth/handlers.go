package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/quire-core/quire/internal/api/middlewares"
	"github.com/quire-core/quire/internal/api/models"
	"github.com/quire-core/quire/internal/repository"
	"github.com/quire-core/quire/internal/store"
	"golang.org/x/crypto/bcrypt"
)

const (
	tokenTTL        = 24 * time.Hour
	refreshTokenTTL = 7 * 24 * time.Hour
)

// RegisterHandler validates a registration request and registers a new user.
func RegisterHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	w.Header().Set("Content-Type", "application/json")

	if store.DB == nil {
		w.WriteHeader(500)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "database_not_connected",
		})

		return
	}

	var req models.RegisterReq

	err := json.NewDecoder(r.Body).Decode(&req)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "invalid_request",
		})

		return
	}

	if code := validateRegisterReq(req); code != "" {
		w.WriteHeader(http.StatusBadRequest)

		json.NewEncoder(w).Encode(map[string]any{
			"error": code,
		})

		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(req.Password),
		12,
	)

	if err != nil {
		w.WriteHeader(500)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "bcrypt_error",
		})

		return
	}

	if err := repository.InsertNewUser(req.Username, string(hashedPassword)); err != nil {
		if store.IsUniqueError(err) {
			w.WriteHeader(http.StatusConflict)

			json.NewEncoder(w).Encode(map[string]any{
				"error": "username_taken",
			})

			return
		}

		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "insert_user_failed",
		})

		return
	}

	w.WriteHeader(http.StatusCreated)

	json.NewEncoder(w).Encode(map[string]any{
		"message": "user_created",
	})
}

// LoginHandler authenticates a user and returns a signed JWT.
func LoginHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	w.Header().Set("Content-Type", "application/json")

	if store.DB == nil {
		w.WriteHeader(500)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "database_not_connected",
		})

		return
	}

	var req models.LoginRequest

	err := json.NewDecoder(r.Body).Decode(&req)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "invalid_request",
		})

		return
	}

	if code := validateLoginReq(req); code != "" {
		w.WriteHeader(http.StatusBadRequest)

		json.NewEncoder(w).Encode(map[string]any{
			"error": code,
		})

		return
	}

	passwordHash, err := repository.GetPasswordWithUsername(req.Username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]any{
				"error": "invalid_credentials",
			})

			return
		}

		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "get_user_failed",
		})

		return
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(passwordHash),
		[]byte(req.Password),
	); err != nil {
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "invalid_credentials",
		})

		return
	}

	userID, err := repository.GetUserIDWithUsername(req.Username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]any{
				"error": "invalid_credentials",
			})

			return
		}

		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "get_user_failed",
		})

		return
	}

	now := time.Now()

	signedToken, err := generateAccessToken(userID, req.Username)
	if err != nil {
		if errors.Is(err, errJWTSecretMissing) {
			w.WriteHeader(http.StatusInternalServerError)

			json.NewEncoder(w).Encode(map[string]any{
				"error": "jwt_secret_missing",
			})

			return
		}

		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "token_generation_failed",
		})

		return
	}

	refreshToken, err := generateRefreshToken()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "refresh_token_generation_failed",
		})

		return
	}

	if err := repository.InsertRefreshToken(
		userID,
		hashRefreshToken(refreshToken),
		now.Add(refreshTokenTTL),
	); err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "save_refresh_token_failed",
		})

		return
	}

	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(map[string]any{
		"token":         signedToken,
		"refresh_token": refreshToken,
	})
}

// RefreshHandler rotates a refresh token and returns a new access token and
// refresh token.
func RefreshHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	w.Header().Set("Content-Type", "application/json")

	if store.DB == nil {
		w.WriteHeader(500)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "database_not_connected",
		})

		return
	}

	var req models.RefreshRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "invalid_request",
		})

		return
	}

	if req.RefreshToken == "" {
		w.WriteHeader(http.StatusBadRequest)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "refresh_token_required",
		})

		return
	}

	tokenHash := hashRefreshToken(req.RefreshToken)

	userID, username, expiresAt, err := repository.GetRefreshToken(tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]any{
				"error": "invalid_refresh_token",
			})

			return
		}

		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "get_refresh_token_failed",
		})

		return
	}

	now := time.Now()

	if !expiresAt.After(now) {
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "invalid_refresh_token",
		})

		return
	}

	newRefreshToken, err := generateRefreshToken()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "refresh_token_generation_failed",
		})

		return
	}

	newToken, err := generateAccessToken(userID, username)
	if err != nil {
		if errors.Is(err, errJWTSecretMissing) {
			w.WriteHeader(http.StatusInternalServerError)

			json.NewEncoder(w).Encode(map[string]any{
				"error": "jwt_secret_missing",
			})

			return
		}

		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "token_generation_failed",
		})

		return
	}

	if err := repository.RotateRefreshToken(
		tokenHash,
		hashRefreshToken(newRefreshToken),
		userID,
		now.Add(refreshTokenTTL),
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]any{
				"error": "invalid_refresh_token",
			})

			return
		}

		w.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "rotate_refresh_token_failed",
		})

		return
	}

	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(map[string]any{
		"token":         newToken,
		"refresh_token": newRefreshToken,
	})
}

// MeHandler returns the claims of the authenticated user. It must be mounted
// behind [middlewares.AuthMiddleware]; it responds with 401 when the request
// carries no claims.
func MeHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	w.Header().Set("Content-Type", "application/json")

	claims, ok := middlewares.GetClaims(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(map[string]any{
			"error": "unauthorized",
		})

		return
	}

	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(map[string]any{
		"user_id":  claims.UserID,
		"username": claims.Username,
	})
}
