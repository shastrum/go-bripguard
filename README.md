# go-bripguard

**go-bripguard** is a lightweight, plug-and-play Go library for browser-based request validation with IP consistency enforcement. It issues a multi-step JavaScript token challenge to the client and verifies the final token to ensure that requests come from a real browser and not from rotating IP bots or headless automation.

---

## ✨ Features

* ✅ Configurable token challenge length and storage backend (in-memory or Redis)
* ✅ JS-based challenge encoded as base64 for easy injection
* ✅ Token-IP binding for rotation detection
* ✅ Middleware setup for selected paths
* ✅ Optional use of functional APIs for custom integration
* ✅ Separate token provider middleware for flexible setups
* ✅ No third-party CAPTCHA or external dependency

---

## 📦 Use Case

Use `bripguard` to protect sensitive endpoints from:

* DDoS bots using IP rotation
* Headless browser automation
* High-frequency scraping tools

---

## 📥 Install

```bash
go get github.com/shastrum/go-bripguard
```

---

## 🛠️ Minimal Setup

```go
import "github.com/shastrum/go-bripguard"

func main() {
    guard := bripguard.New(bripguard.Config{
        BaseURL:           "https://yourdomain.com",
        NumTokens:         3,               // default 3
        OrderSecret:       "ygfvTFUY#@Trvt6udvg8u9p8y2./,><h1ij9-n`7890",
        EncryptionKey:     <>, // RSA Public key
        EncryptionKey:     <>, // RSA private key
        Store:             bripguard.MemoryStore(10*time.Minute),
    })

    // Use GuardOn middleware to enable protection for selected routes
    http.Handle("/", guard.GuardOn([]string{"/login","/checkout","/pay"}))

    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

---

## ⚙️ Config

```go
// Config defines setup options for bripguard
type Config struct {
	// Base URL of your frontend/backend (used for challenge URLs)
	BaseURL         string
	// Number of tokens in the challenge sequence
	NumTokens       int
	// Endpoint that serves individual token steps
	BripPath        string
	// Optional: Final token cookie name
	FinalTokenName  string
	// In-memory, Redis, or custom token store
	Store           Store
	// Optional: token expiry (applies to each token)
	DefaultTokenTTL time.Duration
	// Optional: success remember duration (applies to final token)
	FinalTokenTTL   time.Duration
	// How to read the real client IP
	ReadIP          func(r *http.Request) string
	// for encrypting the tokens
	EncryptionKey   *rsa.PublicKey
	// for encrypting the tokens
	DecryptionKey   *rsa.PrivateKey
	// keep it 8-16 chars only
	OrderSecret     string
}
```

---

## 📘 Public Usable API (Function-Based)

### 1. `guard.GuardOn(paths []string) func(http.Handler) http.Handler`

Returns middleware which protects the specified paths.

* If request lacks a valid final token, returns challenge in response body with `423 Locked` http status
* If token is present and valid, passes the request through
* Automatically serves token / challenge / verification steps at `BripPath` 's subroutes

---

## 🧩 Token Storage Interface

You can provide your own storage backend by implementing the `Store` interface:

```go
type Store interface {
    SetToken(tokenID string, value string, ttl time.Duration) error
	GetAndDelete(key string) (string, error)
}
```

---

## 🧪 Token Flow Summary

1. Client hits a protected route (e.g. `/login`)
2. Server detects no valid token → responds with `challenge` url in body
3. Client is responsible to embed the script tag in DOM with url collected in previous step
3. Client browser fetches & executes actual js-challenge and retrieves N tokens from dynamic paths
4. Final token sent to one of the `BripPath` 's subroutes which then get validated and server responds with set-cookie
5. For further calls from client Server validates full token chain + same IP, with expiry tracking
6. If valid, request is allowed to continue., else the `bripguard` issues a new challenge url

---

## 🚀 Coming Soon

* Fingerprint + cookie counter binding
* Playwright + Puppeteer resistance traps
* Optional encrypted token counters

---

## 📄 License

MIT

---

For help or contributions, visit: [github.com/shastrum/go-bripguard](https://github.com/shastrum/go-bripguard)
