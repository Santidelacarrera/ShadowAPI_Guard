package bola

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Verifier checks JWT signatures (HS256 with a shared secret, RS256 via JWKS) and expiry.
type Verifier struct {
	HS256Secret []byte
	JWKSURL     string
	HTTP        *http.Client
	Now         func() time.Time

	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify returns the claims of a token whose signature and exp/nbf are valid.
func (v *Verifier) Verify(token string) (map[string]any, error) {
	token = strings.TrimPrefix(token, "Bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed jwt")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("bad signature encoding")
	}
	signed := []byte(parts[0] + "." + parts[1])
	switch hdr.Alg {
	case "HS256":
		if len(v.HS256Secret) == 0 {
			return nil, errors.New("HS256 not configured")
		}
		mac := hmac.New(sha256.New, v.HS256Secret)
		mac.Write(signed)
		if !hmac.Equal(mac.Sum(nil), sig) {
			return nil, errors.New("invalid signature")
		}
	case "RS256":
		key, err := v.rsaKey(hdr.Kid)
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(signed)
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, h[:], sig); err != nil {
			return nil, errors.New("invalid signature")
		}
	default: // includes "none": an unsigned token is never trusted when a verifier is configured
		return nil, fmt.Errorf("unsupported alg %q", hdr.Alg)
	}
	var claims map[string]any
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	now := float64(v.now().Unix())
	if exp, ok := claims["exp"].(float64); ok && now >= exp {
		return nil, errors.New("token expired")
	}
	if nbf, ok := claims["nbf"].(float64); ok && now < nbf {
		return nil, errors.New("token not yet valid")
	}
	return claims, nil
}

func decodeSegment(seg string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func (v *Verifier) rsaKey(kid string) (*rsa.PublicKey, error) {
	if v.JWKSURL == "" {
		return nil, errors.New("RS256 not configured")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok && v.now().Sub(v.fetched) < 10*time.Minute {
		return k, nil
	}
	// refresh (unknown kid or stale cache), at most once per 10 s to avoid hammering the IdP
	if v.keys == nil || v.now().Sub(v.fetched) > 10*time.Second {
		if err := v.refresh(); err != nil {
			return nil, err
		}
	}
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown key id %q", kid)
}

func (v *Verifier) refresh() error {
	c := v.HTTP
	if c == nil {
		c = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := c.Get(v.JWKSURL)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	var doc struct {
		Keys []struct{ Kid, Kty, N, E string } `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("parse jwks: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	v.keys, v.fetched = keys, v.now()
	return nil
}
