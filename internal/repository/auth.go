// Package repository provides database operations for Quire's domain objects.
package repository

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/quire-core/quire/internal/store"
)

// InsertNewUser inserts a user with the given username and password hash. It
// wraps the underlying database error, so callers can inspect the result with
// [store.IsUniqueError] to detect a duplicate username.
func InsertNewUser(username, passwordHash string) error {
	if store.DB == nil {
		return errors.New("database not connected")
	}

	_, err := store.DB.Exec(
		`INSERT INTO users (username, password) VALUES (?, ?)`,
		username,
		passwordHash,
	)

	if err != nil {
		return fmt.Errorf("insert new user: %w", err)
	}

	return nil
}

// GetPasswordWithUsername returns the stored password hash for username. It
// returns an error wrapping sql.ErrNoRows when no matching user exists.
func GetPasswordWithUsername(username string) (string, error) {
	if store.DB == nil {
		return "", errors.New("database not connected")
	}

	var passwordHash string

	err := store.DB.QueryRow(
		`SELECT password FROM users WHERE username = ?`,
		username,
	).Scan(&passwordHash)

	if err != nil {
		return "", fmt.Errorf("get password with username: %w", err)
	}

	return passwordHash, nil
}

// GetUserIDWithUsername returns the ID of the user with the given username. It
// returns an error wrapping sql.ErrNoRows when no matching user exists.
func GetUserIDWithUsername(username string) (int64, error) {
	if store.DB == nil {
		return 0, errors.New("database not connected")
	}

	var userID int64

	err := store.DB.QueryRow(
		`SELECT id FROM users WHERE username = ?`,
		username,
	).Scan(&userID)

	if err != nil {
		return 0, fmt.Errorf("get user ID with username: %w", err)
	}

	return userID, nil
}

// InsertRefreshToken stores tokenHash for userID with the given expiry. Callers
// should pass a hash of the refresh token rather than the raw token.
func InsertRefreshToken(userID int64, tokenHash string, expiresAt time.Time) error {
	if store.DB == nil {
		return errors.New("database not connected")
	}

	_, err := store.DB.Exec(
		`INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)`,
		userID,
		tokenHash,
		expiresAt.UTC().Format(time.RFC3339),
	)

	if err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}

	return nil
}

// GetRefreshToken returns the user ID, username, and expiry associated with
// tokenHash. It returns an error wrapping sql.ErrNoRows when no matching token
// exists.
func GetRefreshToken(tokenHash string) (int64, string, time.Time, error) {
	if store.DB == nil {
		return 0, "", time.Time{}, errors.New("database not connected")
	}

	var (
		userID     int64
		username   string
		expiresRaw string
	)

	err := store.DB.QueryRow(
		`SELECT rt.user_id, u.username, rt.expires_at
		 FROM refresh_tokens rt
		 JOIN users u ON u.id = rt.user_id
		 WHERE rt.token = ?`,
		tokenHash,
	).Scan(&userID, &username, &expiresRaw)

	if err != nil {
		return 0, "", time.Time{}, fmt.Errorf("get refresh token: %w", err)
	}

	expiresAt, err := time.Parse(time.RFC3339, expiresRaw)
	if err != nil {
		return 0, "", time.Time{}, fmt.Errorf("parse refresh token expiry: %w", err)
	}

	return userID, username, expiresAt, nil
}

// RotateRefreshToken replaces oldHash with newHash for userID in a single
// transaction. It returns an error wrapping sql.ErrNoRows when oldHash does not
// belong to userID, which can happen when a token is reused concurrently.
func RotateRefreshToken(oldHash, newHash string, userID int64, expiresAt time.Time) error {
	if store.DB == nil {
		return errors.New("database not connected")
	}

	tx, err := store.DB.Begin()
	if err != nil {
		return fmt.Errorf("begin refresh token rotation: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.Exec(
		`DELETE FROM refresh_tokens WHERE token = ? AND user_id = ?`,
		oldHash,
		userID,
	)
	if err != nil {
		return fmt.Errorf("delete old refresh token: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get deleted refresh token count: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("refresh token not found: %w", sql.ErrNoRows)
	}

	_, err = tx.Exec(
		`INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)`,
		userID,
		newHash,
		expiresAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("insert rotated refresh token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit refresh token rotation: %w", err)
	}

	return nil
}
