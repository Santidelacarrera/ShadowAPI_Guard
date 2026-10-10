package bola

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func feed(d *Detector, user, id int, path string) Verdict {
	return d.Check(fmt.Sprintf(path, id), jwt(fmt.Sprintf(`{"sub":"%d","iat":1}`, user)), 200)
}

func TestLearnsOwnershipThenDetectsViolation(t *testing.T) {
	d := New(nil)
	d.Learner = NewLearner()
	// 4 users reading their own objects: no rule exists yet, so nothing can be flagged
	for i := 0; i < 30; i++ {
		u := i%4 + 1
		if feed(d, u, u, "/accounts/%d/statements").Violation {
			t.Fatal("must not flag while learning")
		}
	}
	rules := d.Learner.Rules()
	if len(rules) != 1 || rules[0].Claim != "sub" || !rules[0].Learned {
		t.Fatalf("expected one learned sub rule, got %+v", rules)
	}
	v := feed(d, 1, 2, "/accounts/%d/statements")
	if !v.Violation || v.Subject != "1" {
		t.Fatalf("expected learned-rule violation, got %+v", v)
	}
	if feed(d, 3, 3, "/accounts/%d/statements").Violation {
		t.Fatal("own object flagged")
	}
}

func TestSharedResourcesAreNotLearned(t *testing.T) {
	d := New(nil)
	d.Learner = NewLearner()
	for i := 0; i < 100; i++ { // any user reads any product: ids do not track the caller
		feed(d, i%5+1, (i*7)%50+100, "/products/%d")
	}
	if n := len(d.Learner.Rules()); n != 0 {
		t.Fatalf("learned %d rules for a public resource", n)
	}
}

func TestViolationsDoNotPoisonLearnedRule(t *testing.T) {
	d := New(nil)
	d.Learner = NewLearner()
	for i := 0; i < 30; i++ {
		u := i%4 + 1
		feed(d, u, u, "/u/%d")
	}
	for i := 0; i < 500; i++ { // attacker hammers other people's objects
		feed(d, 1, 2+i%3, "/u/%d")
	}
	if !feed(d, 1, 3, "/u/%d").Violation {
		t.Fatal("rule was diluted by attacker traffic")
	}
}

func TestLearnerNeedsDistinctSubjects(t *testing.T) {
	d := New(nil)
	d.Learner = NewLearner()
	for i := 0; i < 50; i++ {
		feed(d, 1, 1, "/me/%d") // a single user only ever reads their own id
	}
	if len(d.Learner.Rules()) != 0 {
		t.Fatal("single-subject traffic must not promote a rule")
	}
}

func TestLearnerPersistence(t *testing.T) {
	l := NewLearner()
	l.learned[routeParam{"/x/{p2}", "p2"}] = "sub"
	f := t.TempDir() + "/s.json"
	if err := l.Save(f); err != nil {
		t.Fatal(err)
	}
	l2 := NewLearner()
	if err := l2.Load(f); err != nil || len(l2.Rules()) != 1 {
		t.Fatalf("restore failed: %v %+v", err, l2.Rules())
	}
}

// ---- JWT verification --------------------------------------------------------------------------------------------

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func hs256(secret, payload string) string {
	h, p := b64([]byte(`{"alg":"HS256"}`)), b64([]byte(payload))
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(h + "." + p))
	return h + "." + p + "." + b64(m.Sum(nil))
}

func TestVerifyHS256(t *testing.T) {
	v := &Verifier{HS256Secret: []byte("s3")}
	if _, err := v.Verify("Bearer " + hs256("s3", `{"sub":"1"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(hs256("other", `{"sub":"1"}`)); err == nil {
		t.Fatal("bad signature accepted")
	}
	if _, err := v.Verify(hs256("s3", `{"sub":"1","exp":1}`)); err == nil {
		t.Fatal("expired token accepted")
	}
	if _, err := v.Verify(jwt(`{"sub":"1"}`)); err == nil { // alg=none
		t.Fatal("unsigned token accepted")
	}
}

func TestVerifyRS256ViaJWKS(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kid": "k1", "kty": "RSA",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	defer srv.Close()
	sign := func(kid string) string {
		h := b64([]byte(`{"alg":"RS256","kid":"` + kid + `"}`))
		p := b64([]byte(`{"sub":"9"}`))
		sum := sha256.Sum256([]byte(h + "." + p))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		return h + "." + p + "." + b64(sig)
	}
	v := &Verifier{JWKSURL: srv.URL, Now: func() time.Time { return time.Unix(1000, 0) }}
	if c, err := v.Verify(sign("k1")); err != nil || c["sub"] != "9" {
		t.Fatalf("valid RS256 rejected: %v", err)
	}
	if _, err := v.Verify(sign("nope")); err == nil {
		t.Fatal("unknown kid accepted")
	}
	d := New([]Rule{{Template: "/users/{id}", Param: "id", Claim: "sub"}})
	d.Verifier = v
	if !d.Inspect("/users/1", sign("k1")).Violation {
		t.Fatal("verified token should be checked against rules")
	}
	if d.Inspect("/users/1", jwt(`{"sub":"1"}`)).Violation {
		t.Fatal("forged token must be treated as unauthenticated, not as an identity")
	}
}

func BenchmarkInspect(b *testing.B) {
	d := New([]Rule{{Template: "/users/{id}/orders", Param: "id", Claim: "sub"}})
	d.Learner = NewLearner()
	tok := jwt(`{"sub":"42"}`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		d.Check("/users/42/orders?x=1", tok, 200)
	}
}
