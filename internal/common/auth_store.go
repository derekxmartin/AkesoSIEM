package common

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// APIKeyStore manages API keys with an in-memory cache backed by Elasticsearch.
// Keys are loaded from ES at startup and cached for fast authentication lookups.
// Mutations (create, revoke) write-through to ES and update the cache.
type APIKeyStore struct {
	mu       sync.RWMutex
	backend  APIKeyBackend
	byHash   map[string]*APIKey // hash → key (for auth lookups)
	byID     map[string]*APIKey // id → key (for management)
	index    string             // ES index name
}

// APIKeyBackend is the interface for persisting API keys to storage.
// Separating this from Store avoids import cycles and enables test mocks.
type APIKeyBackend interface {
	IndexDoc(ctx context.Context, index, id string, doc []byte) error
	GetDoc(ctx context.Context, index, id string) ([]byte, error)
	SearchDocs(ctx context.Context, index string, query map[string]any) ([]json.RawMessage, error)
	UpdateDoc(ctx context.Context, index, id string, doc []byte) error
}

// NewAPIKeyStore creates a new APIKeyStore with the given backend and index name.
func NewAPIKeyStore(backend APIKeyBackend, indexName string) *APIKeyStore {
	return &APIKeyStore{
		backend: backend,
		byHash:  make(map[string]*APIKey),
		byID:    make(map[string]*APIKey),
		index:   indexName,
	}
}

// LoadAll loads all API keys from the backend into the cache.
// Call this once at startup before serving requests.
func (s *APIKeyStore) LoadAll(ctx context.Context) error {
	query := map[string]any{
		"query": map[string]any{"match_all": map[string]any{}},
		"size":  10000,
	}

	docs, err := s.backend.SearchDocs(ctx, s.index, query)
	if err != nil {
		return fmt.Errorf("loading API keys: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.byHash = make(map[string]*APIKey, len(docs))
	s.byID = make(map[string]*APIKey, len(docs))

	for _, doc := range docs {
		var key APIKey
		if err := json.Unmarshal(doc, &key); err != nil {
			continue // skip malformed keys
		}
		s.byHash[key.Hash] = &key
		s.byID[key.ID] = &key
	}

	return nil
}

// Create generates a new API key, persists it to ES, and adds it to the cache.
// Returns the result containing the plaintext key (shown only once).
func (s *APIKeyStore) Create(ctx context.Context, name string, scopes []string, expiresAt time.Time) (*APIKeyCreateResult, error) {
	result, err := GenerateAPIKey(name, scopes, expiresAt)
	if err != nil {
		return nil, err
	}

	doc, err := json.Marshal(result.Key)
	if err != nil {
		return nil, fmt.Errorf("marshaling API key: %w", err)
	}

	if err := s.backend.IndexDoc(ctx, s.index, result.Key.ID, doc); err != nil {
		return nil, fmt.Errorf("storing API key: %w", err)
	}

	s.mu.Lock()
	s.byHash[result.Key.Hash] = result.Key
	s.byID[result.Key.ID] = result.Key
	s.mu.Unlock()

	return result, nil
}

// Revoke marks an API key as revoked in both the cache and ES.
func (s *APIKeyStore) Revoke(ctx context.Context, id string) error {
	s.mu.Lock()
	key, ok := s.byID[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("API key %q not found", id)
	}

	key.Revoked = true
	key.RevokedAt = time.Now().UTC()
	s.mu.Unlock()

	doc, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("marshaling revoked key: %w", err)
	}

	if err := s.backend.UpdateDoc(ctx, s.index, id, doc); err != nil {
		return fmt.Errorf("updating revoked key in ES: %w", err)
	}

	return nil
}

// Authenticate checks a plaintext API key and returns the key metadata if valid.
// Returns nil if the key is unknown, revoked, or expired.
func (s *APIKeyStore) Authenticate(plaintext string) *APIKey {
	hash := HashAPIKey(plaintext)

	s.mu.RLock()
	key, ok := s.byHash[hash]
	s.mu.RUnlock()

	if !ok {
		return nil
	}

	if !key.IsValid() {
		return nil
	}

	return key
}

// AuthenticateWithScope checks a plaintext API key and verifies it has the given scope.
func (s *APIKeyStore) AuthenticateWithScope(plaintext, scope string) *APIKey {
	key := s.Authenticate(plaintext)
	if key == nil {
		return nil
	}
	if !key.HasScope(scope) {
		return nil
	}
	return key
}

// List returns all API keys (without hashes, for safe display).
func (s *APIKeyStore) List() []*APIKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]*APIKey, 0, len(s.byID))
	for _, key := range s.byID {
		keys = append(keys, key)
	}
	return keys
}

// Get returns a single API key by ID, or nil if not found.
func (s *APIKeyStore) Get(id string) *APIKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byID[id]
}

// Count returns the total number of keys and the number of active (valid) keys.
func (s *APIKeyStore) Count() (total, active int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total = len(s.byID)
	for _, key := range s.byID {
		if key.IsValid() {
			active++
		}
	}
	return
}

// AddStaticKeys adds plaintext keys from config (backwards compatibility).
// These are stored as in-memory-only keys with no ES backing.
func (s *APIKeyStore) AddStaticKeys(keys []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, plaintext := range keys {
		hash := HashAPIKey(plaintext)
		key := &APIKey{
			ID:        fmt.Sprintf("static-%d", i),
			Name:      fmt.Sprintf("static-config-key-%d", i),
			Prefix:    safePrefix(plaintext),
			Hash:      hash,
			CreatedAt: time.Now().UTC(),
		}
		s.byHash[hash] = key
		s.byID[key.ID] = key
	}
}

func safePrefix(key string) string {
	if len(key) > 8 {
		return key[:8] + "..."
	}
	return key + "..."
}
