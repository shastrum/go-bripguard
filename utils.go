package bripguard

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// defaultIPReader returns the client's IP address.
// It checks X-Forwarded-For first, then falls back to RemoteAddr.
func defaultIPReader(r *http.Request) string {

	// Check for X-Forwarded-For header
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// The header may contain multiple IPs, comma-separated
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	// Fallback to RemoteAddr (format: IP:port)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // Use raw if parsing fails
	}
	return host
}

// randomAlphaString returns a random string of [l, r] length from letters
func randomAlphaString(l int, r int) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	if l > r {
		l, r = r, l
	}
	mrandv := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	n := mrandv.Intn(r-l+1) + l
	if n == 0 {
		return "", nil
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := 0; i < n; i++ {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b), nil
}

// buildEncryptionKey uses SHA-256 on (secretHash + orderDeciderStr)
func buildEncryptionKey(orderDeciderStr, secretHash string) []byte {
	key := sha256.Sum256([]byte(secretHash + orderDeciderStr))
	return key[:]
}

// EncryptWrappedOrder generates a token with obfuscated orderNum using AES-CTR
func encryptWrappedOrder(orderNum int, orderDeciderStr, secretHash string) (string, error) {
	key := buildEncryptionKey(orderDeciderStr, secretHash)

	prefix, err := randomAlphaString(1, 2)
	if err != nil {
		return "", err
	}
	suffix, err := randomAlphaString(0, 2)
	if err != nil {
		return "", err
	}

	wrappedOrderStr := prefix + strconv.Itoa(orderNum) + suffix

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	stream := cipher.NewCTR(block, nonce)

	cipherText := make([]byte, len(wrappedOrderStr))
	stream.XORKeyStream(cipherText, []byte(wrappedOrderStr))

	final := append(nonce, cipherText...)
	return base64.RawURLEncoding.EncodeToString(final), nil
}

// DecryptWrappedOrder decrypts encryptedStr and extracts numeric orderNum from wrapped string
func decryptWrappedOrder(encryptedStr, orderDeciderStr, secretHash string) (int, error) {
	key := buildEncryptionKey(orderDeciderStr, secretHash)

	data, err := base64.RawURLEncoding.DecodeString(encryptedStr)
	if err != nil {
		return 0, err
	}

	if len(data) < aes.BlockSize {
		return 0, fmt.Errorf("ciphertext too short")
	}

	nonce := data[:aes.BlockSize]
	cipherText := data[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, err
	}

	stream := cipher.NewCTR(block, nonce)

	plainText := make([]byte, len(cipherText))
	stream.XORKeyStream(plainText, cipherText)

	// Extract digits only (assuming prefix/suffix wrap)
	orderStr := ""
	for _, ch := range plainText {
		if ch >= '0' && ch <= '9' {
			orderStr += string(ch)
		}
	}
	if orderStr == "" {
		return 0, fmt.Errorf("no digits found in decrypted token")
	}

	return strconv.Atoi(orderStr)
}

func getPayloadSlice(payload string, idx int, n int) string {
	ln := len(payload)

	tmn := ln / n
	onebefore := ln % n

	start := onebefore * (tmn + 1)
	end := start + tmn
	if idx < onebefore {
		start = (tmn + 1) * idx
		end = start + tmn + 1
	}

	return payload[start:end]
}

// EncryptWithPublic encrypts payload using the public key
func encryptWithSecret(pub *rsa.PublicKey, payload []byte) ([]byte, error) {
	label := []byte("") // optional
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, payload, label)
}

// DecryptWithPrivate decrypts ciphertext using the private key
func decryptWithSecret(priv *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	label := []byte("") // optional
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, cipherText, label)
}

// encodeIPToCharset encodes the IP address using a non-overlapping custom charset.
func encodeIPToCharset(ip string) string {
	var encoded []byte
	for _, b := range []byte(ip) {
		encoded = append(encoded, ipCharSet[int(b)%len(ipCharSet)])
	}
	return string(encoded)
}

func weaveIpInPayload(ip, payload string) (string, error) {
	encodedIP := encodeIPToCharset(ip)
	result := strings.Builder{}

	i, j := 0, 0 // i = payload index, j = encodedIP index
	totalLen := len(payload) + len(encodedIP)

	mrandv := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	selctors := map[int]bool{
		// 7: true,
		21: true, 31: true, 17: true, 19: true,
	}
	for k := 0; k < totalLen; k++ {
		mrn := mrandv.Intn(32)
		if i >= len(payload) || (j < len(encodedIP) && selctors[mrn]) {
			// Only IP characters left
			result.WriteByte(encodedIP[j])
			j++
		} else {
			// Only payload characters left
			result.WriteByte(payload[i])
			i++
		}
	}

	return result.String(), nil
}

func subtractIp(mixed string, ip string) (string, string) {
	var result strings.Builder

	encodedIP := encodeIPToCharset(ip)

	i := 0 // index for encodedIP

	for _, ch := range mixed {
		if i < len(encodedIP) && ch == rune(encodedIP[i]) {
			i++
		} else {
			result.WriteRune(ch)
		}
	}

	return result.String(), encodedIP
}
