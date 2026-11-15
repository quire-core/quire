// Package store provides the SQLite connection and schema used by Quire.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// DB is the process-wide SQLite handle installed by [ConnectDB] and cleared by
// [CloseDB]. It is nil while no connection is active.
//
// The handle is safe for concurrent database operations, but callers must
// synchronize calls to [ConnectDB] and [CloseDB] with other access to DB.
var DB *sql.DB

// IsUniqueError reports whether err is caused by a UNIQUE constraint
// violation.
func IsUniqueError(err error) bool {
	var sqliteErr *sqlite.Error

	if !errors.As(err, &sqliteErr) {
		return false
	}

	return sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE
}

// ConnectDB opens the SQLite database at dbPath, applies the connection
// pragmas, verifies the connection, and installs the handle in [DB]. Unless
// dbPath begins with ":memory:" or "file:", it creates the database file with
// 0600 permissions.
//
// ConnectDB returns an error if the file cannot be created, the database cannot
// be opened, a pragma fails, or the initial ping fails. On failure, [DB] is left
// unchanged. It does not close a previously installed handle; call [CloseDB]
// before replacing an active connection.
func ConnectDB(dbPath string) error {
	if !strings.HasPrefix(dbPath, ":memory:") && !strings.HasPrefix(dbPath, "file:") {
		file, err := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, 0600)

		if err != nil {
			return fmt.Errorf("create database file: %w", err)
		}

		file.Close()

		if err := os.Chmod(dbPath, 0600); err != nil {
			return fmt.Errorf("set database permissions: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dbPath)

	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}

	// Enable WAL mode and foreign keys for better concurrency and integrity.
	// secure_delete overwrites deleted content so stale ciphertext does not
	// linger in free pages.
	pragmas := []string{
		"PRAGMA journal_mode = WAL;",
		"PRAGMA foreign_keys = ON;",
		"PRAGMA busy_timeout = 5000;",
		"PRAGMA secure_delete = ON;",
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return fmt.Errorf("exec pragma %q: %w", pragma, err)
		}
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return fmt.Errorf("ping database: %w", err)
	}

	DB = db

	return nil
}

// CloseDB closes the active SQLite handle and clears [DB]. It returns nil when
// no handle is active and leaves [DB] set if closing fails.
func CloseDB() error {
	if DB == nil {
		return nil
	}

	if err := DB.Close(); err != nil {
		return fmt.Errorf("close database: %w", err)
	}

	DB = nil

	return nil
}

// CreateTables creates the users table if it does not already exist. It returns
// an error if [DB] is not connected or the schema cannot be applied.
func CreateTables() error {
	if DB == nil {
		return errors.New("database not connected")
	}

	const schema = `
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT NOT NULL UNIQUE,
	password TEXT NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	token TEXT NOT NULL UNIQUE,
	expires_at DATETIME NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)

`

	if _, err := DB.Exec(schema); err != nil {
		return fmt.Errorf("create tables: %w", err)
	}

	return nil
}
