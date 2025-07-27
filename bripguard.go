package bripguard

import (
	"crypto/rsa"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
)

const (
	releasePath string = "/_rl/"
	tokenPath   string = "/_tk/"
	verifyPath  string = "/_vf/"
)

var ipCharSet = []byte("$*()+[!@]{%};:<^&>,.?/)~`#") // Distinct from base64
func IpHashJumble(seed string) {
	if len(seed) > len(ipCharSet) {
		seed = seed[:len(ipCharSet)]
	}
	newSet := ""
	for i := range seed {
		n := len(ipCharSet)
		z := int(byte(seed[i])) % n
		newSet += string(ipCharSet[z])
		ipsetfir := ""
		if z > 0 {
			ipsetfir = string(ipCharSet[0:z])
		}
		ipsetsec := ""
		if z+1 < n {
			ipsetsec = string(ipCharSet[z+1 : n])
		}
		ipCharSet = []byte(ipsetfir + ipsetsec)
	}

	ipCharSet = []byte(newSet + string(ipCharSet))
}

// Config defines setup options for bripguard
type Config struct {
	// Base URL of your frontend/backend (used for challenge URLs)
	BaseURL string
	// Number of tokens in the challenge sequence
	NumTokens int
	// Endpoint that serves individual token steps
	BripPath string
	// Optional: Final token cookie name
	FinalTokenName string
	// In-memory, Redis, or custom token store
	Store Store
	// Optional: token expiry (applies to each token)
	DefaultTokenTTL time.Duration
	// Optional: success remember duration (applies to final token)
	FinalTokenTTL time.Duration
	// How to read the real client IP
	ReadIP func(r *http.Request) string
	// for encrypting the tokens
	EncryptionKey *rsa.PublicKey
	// for encrypting the tokens
	DecryptionKey *rsa.PrivateKey
	// keep it 8-16 chars only
	OrderSecret string
}

// BripGuard holds internal runtime data
type BripGuard struct {
	cfg Config
}

func New(cfg Config) *BripGuard {
	if cfg.BaseURL == "" {
		panic("BripGuard: base url found empty")
	}
	if cfg.NumTokens <= 0 {
		cfg.NumTokens = 3
	}
	if cfg.NumTokens > 8 {
		cfg.NumTokens = 8
	}
	if cfg.BripPath == "" {
		cfg.BripPath = "/_bripf"
	}
	if cfg.FinalTokenName == "" {
		cfg.FinalTokenName = "_bripf"
	}
	if cfg.Store == nil {
		cfg.Store = MemoryStore(10 * time.Minute)
	}
	if cfg.DefaultTokenTTL <= 0 {
		cfg.DefaultTokenTTL = 5 * time.Minute
	}
	if cfg.FinalTokenTTL <= 0 {
		cfg.FinalTokenTTL = 60 * time.Minute
	}
	if cfg.ReadIP == nil {
		cfg.ReadIP = defaultIPReader
	}
	if cfg.EncryptionKey == nil {
		panic("BripGuard: encryption key found empty")
	}
	if cfg.DecryptionKey == nil {
		panic("BripGuard: decryption key found empty")
	}
	if cfg.OrderSecret == "" {
		panic("BripGuard: order secret found empty")
	}

	return &BripGuard{
		cfg: cfg,
	}
}

func asKey(str string) string {
	return "_bripf." + str
}

func (g *BripGuard) CreateSession(delayInMs int) (string, error) {
	sessionId := uuid.New().String()
	if delayInMs < 0 {
		delayInMs = 0
	}
	if err := g.cfg.Store.SetToken(asKey(sessionId), strconv.Itoa(delayInMs), g.cfg.DefaultTokenTTL); err != nil {
		return "", err
	}
	return sessionId, nil
}

func (g *BripGuard) getUrlsBySession(sessionId string) ([]string, string, error) {
	val := strconv.FormatInt(time.Now().UnixMilli(), 10) + "|" + sessionId

	urls := []string{}
	for i := 0; i < g.cfg.NumTokens; i++ {
		keyUUID := uuid.New().String()
		orderDecider64Str, err := randomAlphaString(2, 4)
		if err != nil {
			return nil, "", err
		}
		order64Str, err := encryptWrappedOrder(i, orderDecider64Str, g.cfg.OrderSecret)
		if err != nil {
			return nil, "", err
		}
		if err := g.cfg.Store.SetToken(asKey(keyUUID+":"+strconv.Itoa(i)), val, g.cfg.DefaultTokenTTL); err != nil {
			return nil, "", err
		}
		urls = append(urls, g.cfg.BaseURL+g.cfg.BripPath+tokenPath+orderDecider64Str+"/"+keyUUID+"/"+order64Str)
	}

	return urls, g.cfg.BaseURL + g.cfg.BripPath + verifyPath, nil
}
