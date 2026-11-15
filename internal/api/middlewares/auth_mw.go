// Package middlewares contains HTTP middleware shared by Quire's API routes.
package middlewares

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/quire-core/quire/internal/api/models"
	"github.com/quire-core/quire/internal/config"
)

const bearerScheme = "bearer"

// claimsKey is the context key type for the claims stored by [AuthMiddleware].
type claimsKey struct{}

// AuthMiddleware verifies the Bearer access token in the Authorization header
// and stores its claims in the request context, where handlers can read them
// with [GetClaims]. Requests with a missing, expired, or invalid token are
// rejected with 401 before reaching the wrapped handler.
//
// Because it has the func(http.Handler) http.Handler shape, it can be attached
// to a single route with chi's Router.With:
//
//	r.With(middlewares.AuthMiddleware).Get("/notes", notes.ListHandler)
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret := config.GetJWTSecret()
		if secret == "" {
			writeError(w, http.StatusInternalServerError, "jwt_secret_missing")

			return
		}

		tokenString, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing_token")

			return
		}

		claims := &models.Claims{}

		token, err := jwt.ParseWithClaims(
			tokenString,
			claims,
			func(*jwt.Token) (any, error) {
				return []byte(secret), nil
			},
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
			jwt.WithExpirationRequired(),
		)

		if err != nil || !token.Valid {
			writeError(w, http.StatusUnauthorized, "invalid_token")

			return
		}

		ctx := context.WithValue(r.Context(), claimsKey{}, claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetClaims returns the claims stored by [AuthMiddleware]. The boolean is false
// when the request did not pass through [AuthMiddleware].
func GetClaims(r *http.Request) (*models.Claims, bool) {
	claims, ok := r.Context().Value(claimsKey{}).(*models.Claims)

	return claims, ok
}

// bearerToken extracts the token from an "Authorization: Bearer <token>"
// header. The scheme comparison is case-insensitive, as required by RFC 6750.
func bearerToken(header string) (string, bool) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, bearerScheme) {
		return "", false
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}

	return token, true
}

// writeError writes a JSON error response with the given status and error code.
func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	json.NewEncoder(w).Encode(map[string]any{
		"error": code,
	})
}
