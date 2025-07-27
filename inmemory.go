package bripguard

import (
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
)

type memoryStore struct {
	mu    sync.RWMutex
	cache *cache.Cache
}

// MemoryStore creates a new in-memory token store using go-cache.
func MemoryStore(defaultTTL time.Duration) Store {
	return &memoryStore{
		cache: cache.New(defaultTTL, 2*defaultTTL), // cleanup every 2x TTL
	}
}

func (s *memoryStore) SetToken(tokenID string, value string, ttl time.Duration) error {
	s.cache.Set(tokenID, value, ttl)
	return nil
}

func (s *memoryStore) GetAndDelete(tokenID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, found := s.cache.Get(tokenID)
	if !found {
		s.cache.Delete(tokenID)
		return "", ErrTokenNotFound
	}

	token, ok := raw.(string)
	if !ok {
		s.cache.Delete(tokenID)
		return "", ErrTokenCorrupted
	}
	s.cache.Delete(tokenID)
	return token, nil
}
