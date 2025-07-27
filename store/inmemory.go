package store

import (
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/shastrum/go-bripguard"
)

type memoryStore struct {
	cache *cache.Cache
}

// MemoryStore creates a new in-memory token store using go-cache.
func MemoryStore(defaultTTL time.Duration) bripguard.Store {
	return &memoryStore{
		cache: cache.New(defaultTTL, 2*defaultTTL), // cleanup every 2x TTL
	}
}

func (s *memoryStore) SetToken(tokenID string, value bripguard.TokenInfo, ttl time.Duration) error {
	value.ExpiresAt = time.Now().Add(ttl)
	s.cache.Set(tokenID, value, ttl)
	return nil
}

func (s *memoryStore) GetToken(tokenID string) (bripguard.TokenInfo, error) {
	raw, found := s.cache.Get(tokenID)
	if !found {
		return bripguard.TokenInfo{}, bripguard.ErrTokenNotFound
	}

	token, ok := raw.(bripguard.TokenInfo)
	if !ok {
		return bripguard.TokenInfo{}, bripguard.ErrTokenCorrupted
	}

	if time.Now().After(token.ExpiresAt) {
		return bripguard.TokenInfo{}, bripguard.ErrTokenExpired
	}
	return token, nil
}

func (s *memoryStore) DeleteToken(tokenID string) error {
	s.cache.Delete(tokenID)
	return nil
}
