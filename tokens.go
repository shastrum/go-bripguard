package bripguard

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (g *BripGuard) GenerateToken(r *http.Request) (string, error) {
	// Expected path format: /<orderDeciderStr>/<sharedUUID>/<orderStr>
	pathParts := strings.Split(sanitizeUrl(r.URL.Path), "/")
	if len(pathParts) < 3 {
		return "", fmt.Errorf("brip invalid token path")
	}

	orderDecider64Str := pathParts[len(pathParts)-3]
	keyUUID := pathParts[len(pathParts)-2]
	order64Str := pathParts[len(pathParts)-1]

	// 1. Decrypt orderStr to get orderNum
	orderNum, err := decryptWrappedOrder(order64Str, orderDecider64Str, g.cfg.OrderSecret)
	if err != nil {
		return "", fmt.Errorf("brip failed to decrypt orderStr: %w", err)
	}

	// 2. Get the basePayload from cache (use = get+delete)
	base64Payload, err := g.useChallengePart(keyUUID, orderNum)
	if err != nil {
		return "", fmt.Errorf("brip token part not found or already used: %w", err)
	}
	// base64Payload := base64.URLEncoding.EncodeToString([]byte(basePayload))

	// 3. Slice part of the payload based on orderNum
	part := getPayloadSlice(base64Payload, orderNum, g.cfg.NumTokens)

	// 4. Get IP
	ip := g.cfg.ReadIP(r)
	if ip == "" {
		return "", fmt.Errorf("brip could not determine request IP")
	}

	// 5. Rebuild final payload
	finalPayload, err := weaveIpInPayload(ip, fmt.Sprintf("%s|%s|%s", order64Str, part, orderDecider64Str))
	if err != nil {
		return "", fmt.Errorf("brip weave ip in token failed: %w", err)
	}

	// 6. encypt token
	token, err := encryptWithSecret(g.cfg.EncryptionKey, []byte(finalPayload))
	if err != nil {
		return "", fmt.Errorf("brip failed to generate HMAC: %w", err)
	}

	// 8. Base64 encode the HMAC token
	return base64.RawURLEncoding.EncodeToString(token), nil
}

func (g *BripGuard) VerifyFinalToken(r *http.Request) (string, bool, error) {
	var tokenStr string
	if ck, err := r.Cookie(g.cfg.FinalTokenName); err == nil && ck != nil && ck.Value != "" {
		tokenStr = ck.Value
	} else {
		return tokenStr, false, ErrTokenNotFound
	}

	if v, err := g.VerifyToken(tokenStr, r); err != nil || !v {
		return tokenStr, v, err
	}

	return tokenStr, true, nil
}

func (g *BripGuard) VerifyToken(tokenStr string, r *http.Request) (bool, error) {
	tokens := strings.Split(tokenStr, "|")

	if len(tokens) != g.cfg.NumTokens {
		return false, ErrTokenCorrupted
	}

	ip := g.cfg.ReadIP(r)
	if ip == "" {
		return false, ErrIpNotFound
	}

	finalParts := []string{}
	for i:=0; i<g.cfg.NumTokens; i++ {
		finalParts = append(finalParts, "")
	}

	for _, encoded := range tokens {
		// 1. Decode base64
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return false, ErrTokenCorrupted
		}

		raw, err = decryptWithSecret(g.cfg.DecryptionKey, raw)
		if err != nil {
			return false, ErrTokenCorrupted
		}

		nrw, encip := subtractIp(string(raw), ip)
		if len(string(raw)) != len(nrw)+len(encip) {
			return false, ErrTokenCorrupted
		}

		parts := strings.Split(nrw, "|")
		if len(parts) != 3 && len(parts) != 4 {
			return false, ErrTokenCorrupted
		}
		order64Str := parts[0]
		orderDecider64Str := parts[len(parts)-1]
		// part := parts[1]
		part := nrw[1+len(order64Str) : len(nrw)-len(orderDecider64Str)-1]

		// Decrypt orderStr to get orderNum
		orderNum, err := decryptWrappedOrder(order64Str, orderDecider64Str, g.cfg.OrderSecret)
		if err != nil {
			return false, ErrTokenCorrupted
		}

		finalParts[orderNum] = part
	}

	// Reconstruct final payload and validate
	finalPayload := strings.Join(finalParts, "")
	decoded := string(finalPayload)

	// Validate structure and expiry
	parts := strings.Split(string(decoded), "|")
	if len(parts) != 2 {
		return false, ErrTokenCorrupted
	}
	timestampStr := parts[0]
	sharedUUID := parts[1]

	// Check expiry (e.g., 5 mins)
	ts, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return false, ErrTokenCorrupted
	}

	if time.Since(time.UnixMilli(ts)) > g.cfg.FinalTokenTTL {
		return false, ErrTokenCorrupted
	}

	if _, err := uuid.Parse(sharedUUID); err != nil {
		return false, ErrTokenCorrupted
	}

	return true, nil
}

// UseChallengePart fetches and deletes the stored challenge part (one-time use)
func (g *BripGuard) useChallengePart(orderKey string, orderNum int) (string, error) {
	if g.cfg.Store == nil {
		return "", fmt.Errorf("brip store not initialized")
	}
	key := fmt.Sprintf("%s:%d", orderKey, orderNum)
	return g.cfg.Store.GetAndDelete(asKey(key))
}
