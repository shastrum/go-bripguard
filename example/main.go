package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/shastrum/go-bripguard"
)

func main() {
	port := "3002"
	bripguard.IpHashJumble("297c981ynx`pct9u2xyuycgxhugcjhjxgacauqiuihcbqutbvq78ci7t`xzy7s8y78txt2r6`tt7gt1gqx3")

	mCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rsapbKey, err := parsePublicKey(pub64)
	if err != nil {
		fmt.Println(err)
		return
	}
	rsapvKey, err := parsePrivateKey(priv64)
	if err != nil {
		fmt.Println(err)
		return
	}

	guard := bripguard.New(bripguard.Config{
		BaseURL:       "http://localhost:" + port,
		OrderSecret:   "7n8x176bOIYTI)(&xyliY67R6TR578BUYGygfvTFUY#@Trvt6udvg8u9p8y2./,><h1ij9-n`7890bcn98xpto877t",
		EncryptionKey: rsapbKey,
		DecryptionKey: rsapvKey,
	})

	r := chi.NewRouter()

	r.Use(middleware.RedirectSlashes)
	r.Use(cors.Handler(corsOpts))
	r.Use(guard.GuardOn([]string{"*"}))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("hello there"))
	})

	r.Get("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("hello there, again"))
	})

	// server setup
	startServer, stopServer := setupHttpServer(port, r)
	go startServer()
	defer stopServer()

	<-mCtx.Done()

	fmt.Println("service is stopping")
}

func setupHttpServer(port string, baseRouter *chi.Mux) (func(), func()) {
	// server setup
	server := http.Server{Addr: ":" + port, Handler: baseRouter}
	stop := func() {
		ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
		server.Shutdown(ctx)
		fmt.Println("server shutdown successfully")
	}
	start := func() {
		var err error
		fmt.Printf("server starting at port : %s", port)
		err = server.ListenAndServe()

		if err != http.ErrServerClosed {
			fmt.Println("server starting returned error")
		}
	}

	return start, stop
}

func parsePrivateKey(b64Str string) (*rsa.PrivateKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(b64Str)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		err = errors.New("failed to decode private-pem key block")
		return nil, err
	}

	// openssl genpkey results decide which parsing to use --> PKCS#8 : use ParsePKCS8PrivateKey
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok || rsaKey == nil {
		err := errors.New("private key is not a valid rsa key")
		return nil, err
	}

	return rsaKey, nil
}

func parsePublicKey(b64Str string) (*rsa.PublicKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(b64Str)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("failed to decode public-pem key block")
	}

	// openssl genpkey results decide which parsing to use --> PKCS#8 : use ParsePKCS8PrivateKey
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok || pubKey == nil {
		return nil, errors.New("public key is not a valid rsa key")
	}

	return pubKey, nil
}

var corsOpts = cors.Options{
	AllowedOrigins:   []string{"http://127.0.0.1:5500", "http://localhost:5500"},
	AllowedMethods:   []string{"OPTIONS", "GET", "PUT", "POST", "DELETE"},
	AllowedHeaders:   []string{"Authorization", "X-Forwarded-For", "X-Header-Auth", "Content-Type"},
	AllowCredentials: true,
}

const (
	pub64  string = "" // add base64 public key
	priv64 string = "" // add base64 private key
)
