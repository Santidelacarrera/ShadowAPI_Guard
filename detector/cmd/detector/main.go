package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/santidelacarrera/shadowapi_guard/detector/bola"
	"github.com/santidelacarrera/shadowapi_guard/detector/internal/server"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func loadRules() []bola.Rule {
	// default: /users/{id}... must belong to the token subject
	rules := []bola.Rule{
		{Template: "/users/{id}", Param: "id", Claim: "sub"},
		{Template: "/users/{id}/orders", Param: "id", Claim: "sub"},
		{Template: "/users/{id}/orders/{order}", Param: "id", Claim: "sub"},
	}
	if f := os.Getenv("BOLA_RULES_FILE"); f != "" {
		raw, err := os.ReadFile(f)
		if err != nil {
			log.Fatalf("read rules: %v", err)
		}
		if err := json.Unmarshal(raw, &rules); err != nil {
			log.Fatalf("parse rules: %v", err)
		}
	}
	return rules
}

func buildDetector() *bola.Detector {
	d := bola.New(loadRules())
	if secret, jwks := os.Getenv("JWT_HS256_SECRET"), os.Getenv("JWKS_URL"); secret != "" || jwks != "" {
		d.Verifier = &bola.Verifier{HS256Secret: []byte(secret), JWKSURL: jwks}
		log.Print("JWT signature verification enabled")
	} else {
		log.Print("WARNING: JWT signatures are NOT verified (set JWT_HS256_SECRET or JWKS_URL)")
	}
	if env("BOLA_LEARN", "1") == "1" {
		d.Learner = bola.NewLearner()
		if f := os.Getenv("LEARN_STATE_FILE"); f != "" {
			if err := d.Learner.Load(f); err != nil && !os.IsNotExist(err) {
				log.Printf("load learned rules: %v", err)
			}
		}
	}
	return d
}

func main() {
	det := buildDetector()
	srv := server.New(det, env("CONTROL_PLANE_URL", "http://localhost:8000"), os.Getenv("API_KEY"))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if f := os.Getenv("LEARN_STATE_FILE"); f != "" && det.Learner != nil {
		go func() {
			for t := time.NewTicker(time.Minute); ; {
				select {
				case <-t.C:
					det.Learner.Save(f)
				case <-ctx.Done():
					det.Learner.Save(f)
					return
				}
			}
		}()
	}
	go srv.Run(ctx)
	addr := env("LISTEN_ADDR", ":8081")
	hs := &http.Server{Addr: addr, Handler: srv.Handler()}
	go func() { <-ctx.Done(); hs.Shutdown(context.Background()) }()
	log.Printf("detector listening on %s -> %s", addr, srv.ControlURL)
	if err := hs.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
