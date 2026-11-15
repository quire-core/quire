// Package config manages Quire's user configuration directory and the
// environment variables loaded from its .env file.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
)

const (
	envFileName   = ".env"
	jwtSecretKey  = "JWT_SECRET"
	jwtSecretSize = 32 // bytes of entropy, equivalent to 256 bits
)

var quirePath string

var requiredEnvs = []string{
	jwtSecretKey,
}

// Init ensures that the Quire configuration directory (~/.quire) exists and
// loads its .env file into the process environment. It creates the file when
// missing and fills JWT_SECRET with a securely generated value when the entry is
// absent or empty. Variables already present in the process environment take
// precedence over values from the file.
//
// Init must be called before [GetQuirePath] and before the values from the .env
// file are observable through [GetJWTSecret] and [CheckEnvs].
func Init() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("config: get user home dir: %w", err)
	}

	quirePath = filepath.Join(home, ".quire")

	if err := os.MkdirAll(quirePath, 0755); err != nil {
		return fmt.Errorf("config: create .quire folder: %w", err)
	}

	envPath := filepath.Join(quirePath, envFileName)

	if err := ensureJWTSecret(envPath); err != nil {
		return fmt.Errorf("config: ensure JWT secret: %w", err)
	}

	if err := godotenv.Load(envPath); err != nil {
		return fmt.Errorf("config: load env file: %w", err)
	}

	return nil
}

// ensureJWTSecret makes sure envPath contains a non-empty JWT_SECRET. When the
// entry is missing or empty, it generates a new secret and preserves all other
// entries in the file.
func ensureJWTSecret(envPath string) error {
	content, err := os.ReadFile(envPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read env file: %w", err)
	}

	values, err := godotenv.Unmarshal(string(content))
	if err != nil {
		return fmt.Errorf("parse env file: %w", err)
	}

	if strings.TrimSpace(values[jwtSecretKey]) != "" {
		return nil
	}

	secret, err := generateJWTSecret()
	if err != nil {
		return err
	}

	updated := setEnvValue(string(content), jwtSecretKey, secret)

	if err := writeEnvFile(envPath, updated); err != nil {
		return err
	}

	return nil
}

// generateJWTSecret returns a URL-safe random secret with 256 bits of entropy.
func generateJWTSecret() (string, error) {
	random := make([]byte, jwtSecretSize)

	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate JWT secret: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(random), nil
}

// setEnvValue returns content with key assigned to value. An existing
// assignment is replaced in place; otherwise a new entry is appended. Comments
// and all other entries are preserved.
func setEnvValue(content, key, value string) string {
	lines := strings.Split(content, "\n")
	replaced := false

	for i, line := range lines {
		name, ok := envLineKey(line)
		if !ok || name != key {
			continue
		}

		lines[i] = key + "=" + value
		replaced = true
	}

	if replaced {
		return strings.Join(lines, "\n")
	}

	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	return content + key + "=" + value + "\n"
}

// envLineKey returns the key assigned on a dotenv line and reports whether the
// line contains an assignment. Comments and malformed lines are ignored.
func envLineKey(line string) (string, bool) {
	line = strings.TrimSpace(line)

	if line == "" || strings.HasPrefix(line, "#") {
		return "", false
	}

	if strings.HasPrefix(line, "export ") || strings.HasPrefix(line, "export\t") {
		line = strings.TrimSpace(line[len("export"):])
	}

	key, _, ok := strings.Cut(line, "=")
	if !ok {
		return "", false
	}

	return strings.TrimSpace(key), true
}

// writeEnvFile atomically replaces envPath with content. The temporary file is
// created with 0600 permissions so the secret is never readable by others.
func writeEnvFile(envPath, content string) error {
	file, err := os.CreateTemp(filepath.Dir(envPath), ".env-*")
	if err != nil {
		return fmt.Errorf("create env file: %w", err)
	}

	tmpPath := file.Name()

	if _, err := file.WriteString(content); err != nil {
		file.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write env file: %w", err)
	}

	if err := file.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close env file: %w", err)
	}

	if err := os.Rename(tmpPath, envPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("replace env file: %w", err)
	}

	return nil
}

// GetQuirePath returns the absolute path of the Quire configuration directory
// (~/.quire). It returns an empty string if [Init] has not been called.
func GetQuirePath() string {
	return quirePath
}

// CheckEnvs verifies that all required environment variables are set
// and not empty.
func CheckEnvs() error {
	for _, key := range requiredEnvs {
		if strings.TrimSpace(os.Getenv(key)) == "" {
			return fmt.Errorf("config: environment variable %s is empty", key)
		}
	}

	return nil
}

// GetJWTSecret returns the value of the JWT_SECRET environment variable. The
// result is empty if the variable is unset; call [CheckEnvs] to verify that it
// is configured.
func GetJWTSecret() string {
	return os.Getenv("JWT_SECRET")
}
