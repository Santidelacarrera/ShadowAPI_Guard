package bola

import (
	"encoding/base64"
	"testing"
)

func jwt(payload string) string {
	e := base64.RawURLEncoding.EncodeToString
	return "Bearer " + e([]byte(`{"alg":"none"}`)) + "." + e([]byte(payload)) + ".sig"
}

func TestInspect(t *testing.T) {
	d := New([]Rule{{Template: "/users/{id}/orders", Param: "id", Claim: "sub"}})
	cases := []struct {
		name, path, auth string
		violation        bool
	}{
		{"owner", "/users/42/orders", jwt(`{"sub":"42"}`), false},
		{"other user", "/users/43/orders", jwt(`{"sub":"42"}`), true},
		{"unmatched route", "/health", jwt(`{"sub":"42"}`), false},
		{"no token", "/users/43/orders", "", false},
	}
	for _, c := range cases {
		if got := d.Inspect(c.path, c.auth).Violation; got != c.violation {
			t.Errorf("%s: violation=%v, want %v", c.name, got, c.violation)
		}
	}
}

func TestSubjectAndQueryString(t *testing.T) {
	d := New([]Rule{{Template: "/users/{id}", Param: "id", Claim: "sub"}})
	v := d.Inspect("/users/7?expand=1", jwt(`{"sub":"7"}`))
	if v.Violation || v.Subject != "7" {
		t.Fatalf("unexpected verdict %+v", v)
	}
	if !d.Inspect("/users/8?expand=1", jwt(`{"sub":"7"}`)).Violation {
		t.Fatal("query string must not hide a violation")
	}
}
