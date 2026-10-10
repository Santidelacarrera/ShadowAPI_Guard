package bola

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

var dynSeg = regexp.MustCompile(`^(-?\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{24})$`)

// Learner infers ownership rules from traffic: a (route, path parameter, claim) triple is
// promoted to a rule once, across enough requests and distinct users, the parameter value
// equals the claim almost every time ("/users/{id} is always the caller's own id").
type Learner struct {
	MinSamples  int     // requests observed before a rule can be promoted
	MinSubjects int     // distinct identities that matched
	MinRatio    float64 // fraction of requests where parameter == claim
	MaxKeys     int     // memory bound against attacker-chosen paths

	mu      sync.Mutex
	stats   map[statKey]*stat
	learned map[routeParam]string // route+param -> claim
}

type routeParam struct{ Template, Param string }
type statKey struct {
	routeParam
	Claim string
}
type stat struct {
	Total, Matches int
	Subjects       map[string]struct{}
}

func NewLearner() *Learner {
	return &Learner{MinSamples: 20, MinSubjects: 3, MinRatio: 0.9, MaxKeys: 20000,
		stats: map[statKey]*stat{}, learned: map[routeParam]string{}}
}

// shape turns a path into a template whose dynamic segments are named p<index>.
func shape(path string) (template string, vals map[string]string) {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	segs := strings.Split(path, "/")
	vals = map[string]string{}
	for i, s := range segs {
		if dynSeg.MatchString(s) {
			name := fmt.Sprintf("p%d", i)
			vals[name] = s
			segs[i] = "{" + name + "}"
		}
	}
	return strings.TrimRight(strings.Join(segs, "/"), "/"), vals
}

var ignoredClaims = map[string]bool{"exp": true, "iat": true, "nbf": true, "auth_time": true}

func claimStrings(claims map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range claims {
		if ignoredClaims[k] || len(out) >= 12 {
			continue
		}
		switch t := v.(type) {
		case string:
			out[k] = t
		case float64:
			out[k] = fmt.Sprintf("%d", int64(t))
		}
	}
	return out
}

// Observe feeds one successful (2xx) authenticated request into the statistics.
func (l *Learner) Observe(path string, claims map[string]any) {
	tpl, vals := shape(path)
	if len(vals) == 0 {
		return
	}
	cs := claimStrings(claims)
	l.mu.Lock()
	defer l.mu.Unlock()
	for param, val := range vals {
		rp := routeParam{tpl, param}
		if _, done := l.learned[rp]; done {
			continue // never learn from traffic on an already-learned route: violations must not dilute the rule
		}
		for claim, cv := range cs {
			k := statKey{rp, claim}
			st := l.stats[k]
			if st == nil {
				if len(l.stats) >= l.MaxKeys {
					continue
				}
				st = &stat{Subjects: map[string]struct{}{}}
				l.stats[k] = st
			}
			st.Total++
			if cv == val {
				st.Matches++
				if len(st.Subjects) < 1000 {
					st.Subjects[cv] = struct{}{}
				}
			}
			l.maybePromote(k, st)
		}
	}
}

func (l *Learner) maybePromote(k statKey, st *stat) {
	if st.Total < l.MinSamples || len(st.Subjects) < l.MinSubjects ||
		float64(st.Matches)/float64(st.Total) < l.MinRatio {
		return
	}
	if _, done := l.learned[k.routeParam]; !done {
		l.learned[k.routeParam] = k.Claim
	}
}

// Rules returns the learned rules (stable order).
func (l *Learner) Rules() []Rule {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Rule, 0, len(l.learned))
	for rp, claim := range l.learned {
		out = append(out, Rule{Template: rp.Template, Param: rp.Param, Claim: claim, Learned: true})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Template+out[i].Param < out[j].Template+out[j].Param })
	return out
}

type snapshot struct {
	Learned []Rule `json:"learned"`
}

// Save/Load persist only the promoted rules (not raw statistics).
func (l *Learner) Save(file string) error {
	b, _ := json.Marshal(snapshot{Learned: l.Rules()})
	return os.WriteFile(file, b, 0o600)
}

func (l *Learner) Load(file string) error {
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var s snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range s.Learned {
		l.learned[routeParam{r.Template, r.Param}] = r.Claim
	}
	return nil
}
