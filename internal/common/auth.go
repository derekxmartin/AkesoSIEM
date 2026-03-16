package common

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// APIKey represents a stored API key for authentication.
type APIKey struct {
	// ID is the unique identifier for the key (used for revocation/lookup).
	ID string `json:"id"`

	// Name is a human-readable label for the key (e.g., "ingest-prod-01").
	Name string `json:"name"`

	// Prefix is the first 8 characters of the key, stored for identification
	// without exposing the full key. Displayed as "sk_xxxxxxxx...".
	Prefix string `json:"prefix"`

	// Hash is the SHA-256 hash of the full key. Used for authentication
	// without storing the plaintext key.
	Hash string `json:"hash"`

	// CreatedAt is when the key was created.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when the key expires (zero value means no expiration).
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// Revoked indicates whether the key has been revoked.
	Revoked bool `json:"revoked"`

	// RevokedAt is when the key was revoked (zero if not revoked).
	RevokedAt time.Time `json:"revoked_at,omitempty"`

	// Scopes defines what the key is authorized to do.
	// Currently: "ingest", "query", "admin". Empty means all scopes.
	Scopes []string `json:"scopes,omitempty"`
}

// APIKeyCreateResult is returned when a new API key is created.
// The PlaintextKey is only available at creation time — it is never stored.
type APIKeyCreateResult struct {
	Key          *APIKey `json:"key"`
	PlaintextKey string  `json:"plaintext_key"` // only shown once
}

// GenerateAPIKey creates a new API key with the given name and scopes.
// Returns the key metadata and the plaintext key (shown only once).
func GenerateAPIKey(name string, scopes []string, expiresAt time.Time) (*APIKeyCreateResult, error) {
	// Generate 32 random bytes (256 bits of entropy).
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generating random key: %w", err)
	}

	// Format: sk_<hex> (64 hex chars = 32 bytes).
	plaintextKey := "sk_" + hex.EncodeToString(raw)

	// Hash the full key for storage.
	hash := HashAPIKey(plaintextKey)

	// Generate a unique ID.
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("generating key ID: %w", err)
	}
	id := hex.EncodeToString(idBytes)

	key := &APIKey{
		ID:        id,
		Name:      name,
		Prefix:    plaintextKey[:11], // "sk_" + first 8 hex chars
		Hash:      hash,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
		Scopes:    scopes,
	}

	return &APIKeyCreateResult{
		Key:          key,
		PlaintextKey: plaintextKey,
	}, nil
}

// HashAPIKey returns the SHA-256 hex digest of a plaintext API key.
func HashAPIKey(plaintext string) string {
	h := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(h[:])
}

// IsExpired returns true if the key has a non-zero expiration that is in the past.
func (k *APIKey) IsExpired() bool {
	if k.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().UTC().After(k.ExpiresAt)
}

// IsValid returns true if the key is neither revoked nor expired.
func (k *APIKey) IsValid() bool {
	return !k.Revoked && !k.IsExpired()
}

// HasScope returns true if the key has the given scope, or has no scope
// restrictions (empty scopes = all access).
func (k *APIKey) HasScope(scope string) bool {
	if len(k.Scopes) == 0 {
		return true
	}
	for _, s := range k.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}
