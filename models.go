package bripguard

import (
	"errors"
	"time"
)

// Store is an interface for storing and retrieving tokens.
// You can implement it with memory, Redis, or anything else.
type Store interface {
	SetToken(tokenID string, value string, ttl time.Duration) error
	GetAndDelete(key string) (string, error)
}

var (
	ErrIpNotFound     = errors.New("brip ip not found")
	ErrTokenNotFound  = errors.New("brip token not found")
	ErrTokenExpired   = errors.New("brip token expired")
	ErrTokenCorrupted = errors.New("brip token data corrupted")
)
