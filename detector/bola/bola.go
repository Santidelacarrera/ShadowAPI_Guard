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
	Learned  bool `json:",omitempty"` // true when inferred from traffic instead of configured
}

// Verdict is the outcome of inspecting one request.
type Verdict struct {
	Violation bool
	Reason    string
	Subject   string // value of the "sub" claim, when present
}

// Detector evaluates requests against a set of ownership rules.
type Detector struct {
	rules    []Rule
	Verifier *Verifier // optional: when set, tokens must carry a valid signature
	Learner  *Learner  // optional: infers ownership rules from traffic
}

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
	v, _ := d.inspect(path, authorization)
	return v
}

func (d *Detector) claims(authorization string) (map[string]any, error) {
	if d.Verifier != nil {
		return d.Verifier.Verify(authorization)
	}
	return Claims(authorization)
}

// inspect also returns the claims so callers can feed the learner without re-parsing.
func (d *Detector) inspect(path, authorization string) (Verdict, map[string]any) {
	claims, err := d.claims(authorization)
	if err != nil {
		return Verdict{Reason: "unauthenticated: " + err.Error()}, nil
	}
	rules := d.rules
	if d.Learner != nil {
		rules = append(append([]Rule{}, d.rules...), d.Learner.Rules()...)
	}
	sub, _ := claims["sub"].(string)
	for _, r := range rules {
		vars, ok := match(r.Template, path)
		if !ok {
			continue
		}
		got := claimString(claims[r.Claim])
		if want := vars[r.Param]; got != want {
			why := fmt.Sprintf("claim %q=%q does not own %s=%q", r.Claim, got, r.Param, want)
			if r.Learned {
				why += " (learned rule)"
			}
			return Verdict{true, why, sub}, claims
		}
	}
	return Verdict{Subject: sub}, claims
}

func claimString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%d", int64(t))
	}
	return ""
}

// Check inspects a request and, when it succeeded (2xx) without violating a rule, learns from it.
// status 0 means "unknown" (e.g. the eBPF probe sees requests only) and is treated as non-learnable.
func (d *Detector) Check(path, authorization string, status int) Verdict {
	v, claims := d.inspect(path, authorization)
	if claims != nil && !v.Violation && d.Learner != nil && status >= 200 && status < 300 {
		d.Learner.Observe(path, claims)
	}
	return v
}
