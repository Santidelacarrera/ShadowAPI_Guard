package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/santidelacarrera/shadowapi_guard/detector/bola"
)

func tok(payload string) string {
	e := base64.RawURLEncoding.EncodeToString
	return "Bearer " + e([]byte(`{}`)) + "." + e([]byte(payload)) + ".s"
}

func newSrv(cp string) *Server {
	return New(bola.New([]bola.Rule{{Template: "/users/{id}", Param: "id", Claim: "sub"}}), cp, "k")
}

func TestProcessDropsAuthorizationAndFlags(t *testing.T) {
	s := newSrv("")
	out := s.Process(InEvent{Method: "GET", Path: "/users/2", Status: 200, Authorization: tok(`{"sub":"1"}`)})
	if !out.Bola.Violation || out.Subject != "1" {
		t.Fatalf("expected violation, got %+v", out)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "Bearer") || strings.Contains(strings.ToLower(string(b)), "authorization") {
		t.Fatal("authorization leaked into outbound event")
	}
	if s.Process(InEvent{Method: "GET", Path: "/users/2", Status: 403, Authorization: tok(`{"sub":"1"}`)}).Bola.Violation {
		t.Fatal("denied request must not count as BOLA")
	}
}

func TestForwardsBatchToControlPlane(t *testing.T) {
	got := make(chan []OutEvent, 1)
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "k" {
			w.WriteHeader(401)
			return
		}
		var b []OutEvent
		json.NewDecoder(r.Body).Decode(&b)
		got <- b
		w.WriteHeader(202)
	}))
	defer cp.Close()
	s := newSrv(cp.URL)
	req := httptest.NewRequest("POST", "/events", strings.NewReader(`[{"method":"GET","path":"/users/9","status":200,"authorization":"`+tok(`{"sub":"1"}`)+`"}]`))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 202 {
		t.Fatalf("status %d", rec.Code)
	}
	if err := s.send([]OutEvent{<-s.queue}); err != nil {
		t.Fatal(err)
	}
	b := <-got
	if len(b) != 1 || !b[0].Bola.Violation {
		t.Fatalf("unexpected forwarded batch %+v", b)
	}
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/events", strings.NewReader(`{"not":"array"}`)))
	if rec.Code != 400 {
		t.Fatal("non-array must be rejected")
	}
}
