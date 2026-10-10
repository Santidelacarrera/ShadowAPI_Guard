// Package bola detects Broken Object Level Authorization (BOLA/IDOR) by
// comparing JWT claims against dynamic variables of the request URI.
package bola

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Rule binds a path parameter of a route template to a JWT claim that must
// match it, e.g. {Template: "/users/{id}", Param: "id", Claim: "sub"}.
type Rule struct {
	Template string
	Param    string
	Claim    string
}

// Verdict is the outcome of inspecting one request.
type Verdict struct {
	Violation bool
	Reason    string
	Subject   string // value of the "sub" claim, when present
}

// Detector evaluates requests against a set of ownership rules.
type Detector struct{ rules []Rule }

func New(rules []Rule) *Detector { return &Detector{rules: rules} }

// Claims extracts the payload of a JWT. The signature is NOT verified: the
// gateway/sidecar is expected to have authenticated the token already; this
// engine only correlates identity with the requested object.
func Claims(token string) (map[string]any, error) {
	token = strings.TrimPrefix(token, "Bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed jwt")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	return c, nil
}

// match extracts template variables from path, or returns false.
func match(template, path string) (map[string]string, bool) {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	t := strings.Split(strings.Trim(template, "/"), "/")
	p := strings.Split(strings.Trim(path, "/"), "/")
	if len(t) != len(p) {
		return nil, false
	}
	vars := map[string]string{}
	for i := range t {
		if strings.HasPrefix(t[i], "{") && strings.HasSuffix(t[i], "}") {
			vars[t[i][1:len(t[i])-1]] = p[i]
		} else if t[i] != p[i] {
			return nil, false
		}
	}
	return vars, true
}

// Inspect returns a violation when the object referenced in path does not
// belong to the identity carried by the JWT.
func (d *Detector) Inspect(path, authorization string) Verdict {
	claims, err := Claims(authorization)
	if err != nil {
		return Verdict{Reason: "unauthenticated: " + err.Error()}
	}
	sub, _ := claims["sub"].(string)
	for _, r := range d.rules {
		vars, ok := match(r.Template, path)
		if !ok {
			continue
		}
		got, _ := claims[r.Claim].(string)
		if want := vars[r.Param]; got != want {
			return Verdict{true, fmt.Sprintf("claim %q=%q does not own %s=%q", r.Claim, got, r.Param, want), sub}
		}
	}
	return Verdict{Subject: sub}
}
