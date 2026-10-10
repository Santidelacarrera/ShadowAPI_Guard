// Package server receives raw L7 events from probes, runs BOLA detection and
// forwards sanitised events (never the Authorization header) to the control plane.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/santidelacarrera/shadowapi_guard/detector/bola"
)

// InEvent is what probes/gateways send. Authorization is consumed here and never forwarded.
type InEvent struct {
	Ts            float64 `json:"ts,omitempty"`
	Method        string  `json:"method"`
	Path          string  `json:"path"`
	Host          string  `json:"host,omitempty"`
	Status        int     `json:"status,omitempty"`
	ReqBody       string  `json:"req_body,omitempty"`
	RespBody      string  `json:"resp_body,omitempty"`
	Authorization string  `json:"authorization,omitempty"`
	Source        string  `json:"source,omitempty"`
}

type OutVerdict struct {
	Violation bool   `json:"violation"`
	Reason    string `json:"reason"`
}

type OutEvent struct {
	Ts       float64    `json:"ts,omitempty"`
	Method   string     `json:"method"`
	Path     string     `json:"path"`
	Host     string     `json:"host,omitempty"`
	Status   int        `json:"status"`
	ReqBody  string     `json:"req_body,omitempty"`
	RespBody string     `json:"resp_body,omitempty"`
	Subject  string     `json:"subject,omitempty"`
	Bola     OutVerdict `json:"bola"`
	Source   string     `json:"source,omitempty"`
}

type Server struct {
	Detector   *bola.Detector
	ControlURL string // e.g. http://control-plane:8000
	APIKey     string
	HTTP       *http.Client
	queue      chan OutEvent
}

func New(d *bola.Detector, controlURL, apiKey string) *Server {
	return &Server{Detector: d, ControlURL: controlURL, APIKey: apiKey,
		HTTP: &http.Client{Timeout: 10 * time.Second}, queue: make(chan OutEvent, 10000)}
}

// Process converts an inbound event, applying BOLA detection.
func (s *Server) Process(in InEvent) OutEvent {
	out := OutEvent{Ts: in.Ts, Method: in.Method, Path: in.Path, Host: in.Host, Status: in.Status,
		ReqBody: in.ReqBody, RespBody: in.RespBody, Source: in.Source}
	if in.Authorization != "" {
		v := s.Detector.Inspect(in.Path, in.Authorization)
		out.Bola = OutVerdict{Violation: v.Violation, Reason: v.Reason}
		out.Subject = v.Subject
		// a request the application rejected was not a successful object access
		if in.Status >= 400 {
			out.Bola.Violation = false
		}
	}
	return out
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"status":"ok"}`)) })
	mux.HandleFunc("POST /events", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
		var batch []InEvent
		dec := json.NewDecoder(r.Body)
		tok, err := dec.Token()
		if err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if d, ok := tok.(json.Delim); ok && d == '[' {
			for dec.More() {
				var e InEvent
				if err := dec.Decode(&e); err != nil {
					http.Error(w, "invalid event", http.StatusBadRequest)
					return
				}
				batch = append(batch, e)
			}
		} else {
			http.Error(w, "expected a JSON array of events", http.StatusBadRequest)
			return
		}
		dropped := 0
		for _, e := range batch {
			select {
			case s.queue <- s.Process(e):
			default:
				dropped++
			}
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]int{"accepted": len(batch) - dropped, "dropped": dropped})
	})
	return mux
}

// Run flushes queued events to the control plane in batches until ctx is cancelled.
func (s *Server) Run(ctx context.Context) {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	var batch []OutEvent
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.send(batch); err != nil {
			log.Printf("forward failed (%d events kept for retry): %v", len(batch), err)
			if len(batch) > 20000 { // bound memory when the control plane is down
				batch = batch[len(batch)-10000:]
			}
			return
		}
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case e := <-s.queue:
			batch = append(batch, e)
			if len(batch) >= 200 {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

func (s *Server) send(batch []OutEvent) error {
	body, _ := json.Marshal(batch)
	req, _ := http.NewRequest(http.MethodPost, s.ControlURL+"/events", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if s.APIKey != "" {
		req.Header.Set("X-API-Key", s.APIKey)
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return &statusErr{resp.StatusCode}
	}
	return nil
}

type statusErr struct{ code int }

func (e *statusErr) Error() string { return "control plane returned " + http.StatusText(e.code) }
