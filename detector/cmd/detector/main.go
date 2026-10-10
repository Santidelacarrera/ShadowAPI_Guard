package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

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

func main() {
	srv := server.New(bola.New(loadRules()), env("CONTROL_PLANE_URL", "http://localhost:8000"), os.Getenv("API_KEY"))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go srv.Run(ctx)
	addr := env("LISTEN_ADDR", ":8081")
	hs := &http.Server{Addr: addr, Handler: srv.Handler()}
	go func() { <-ctx.Done(); hs.Shutdown(context.Background()) }()
	log.Printf("detector listening on %s -> %s", addr, srv.ControlURL)
	if err := hs.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
