package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/timeomy/tollgate/internal/identity"
)

// HTTP header names from the MCP streamable HTTP transport.
const (
	headerSessionID = "Mcp-Session-Id"
	headerProtocol  = "Mcp-Protocol-Version"
)

// Backend is the upstream side of one HTTP session.
type Backend struct {
	Interceptor Interceptor
	Upstream    UpstreamConn
	// Stop shuts the upstream down (for a command: stdin close, then signals).
	Stop func() error
}

// UpstreamConn is the subset of mcp.Connection the HTTP server needs.
type UpstreamConn interface {
	Read(context.Context) (jsonrpc.Message, error)
	Write(context.Context, jsonrpc.Message) error
	Close() error
}

// HTTPOptions configures HTTPServer.
type HTTPOptions struct {
	// Authenticate maps a request to an agent (bearer token lookup).
	Authenticate func(*http.Request) (identity.Agent, bool)
	// NewBackend starts the upstream and policy session for a new MCP session.
	NewBackend func(ctx context.Context, agent identity.Agent, sessionID string) (*Backend, error)
	// AllowedOrigins lists extra browser origins allowed besides loopback.
	AllowedOrigins []string
	MaxBodyBytes   int64
	IdleTimeout    time.Duration
	// MaxSessions and MaxSessionsPerAgent cap concurrent sessions; each
	// session runs its own upstream. Zero means the defaults (64 and 8).
	MaxSessions         int
	MaxSessionsPerAgent int
	Logger              *slog.Logger
}

// HTTPServer is Tollgate's MCP streamable HTTP endpoint.
//
// Scope (v0.1): clients POST single JSON-RPC messages and receive
// application/json responses; sessions are created by initialize and ended by
// DELETE or idleness. The optional GET event stream is not offered (405, as
// the transport spec permits), so server-initiated requests other than ping
// are answered with "method not found" and upstream notifications are dropped.
// Each session gets its own upstream connection and policy session.
type HTTPServer struct {
	opts     HTTPOptions
	log      *slog.Logger
	mu       sync.Mutex
	sessions map[string]*httpSession
	starting map[string]int // sessions being started, by agent
	stop     chan struct{}
	stopOnce sync.Once
}

// NewHTTPServer validates options and starts the idle-session reaper.
func NewHTTPServer(opts HTTPOptions) (*HTTPServer, error) {
	if opts.Authenticate == nil || opts.NewBackend == nil {
		return nil, errors.New("proxy: HTTP server needs Authenticate and NewBackend")
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 4 << 20
	}
	if opts.MaxSessions <= 0 {
		opts.MaxSessions = 64
	}
	if opts.MaxSessionsPerAgent <= 0 {
		opts.MaxSessionsPerAgent = 8
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 30 * time.Minute
	}
	l := opts.Logger
	if l == nil {
		l = slog.New(slog.DiscardHandler)
	}
	s := &HTTPServer{opts: opts, log: l, sessions: map[string]*httpSession{}, starting: map[string]int{}, stop: make(chan struct{})}
	go s.reap()
	return s, nil
}

// ServeHTTP implements http.Handler.
func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.originAllowed(r) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}
	agent, ok := s.opts.Authenticate(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tollgate"`)
		http.Error(w, "missing or invalid bearer token", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodPost:
		s.servePOST(w, r, agent)
	case http.MethodDelete:
		s.serveDELETE(w, r, agent)
	default:
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "method not allowed (Tollgate does not offer a GET event stream)", http.StatusMethodNotAllowed)
	}
}

func (s *HTTPServer) servePOST(w http.ResponseWriter, r *http.Request, agent identity.Agent) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(ct), "application/json") {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.opts.MaxBodyBytes))
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 && trimmed[0] == '[' {
		http.Error(w, "JSON-RPC batches are not supported", http.StatusBadRequest)
		return
	}
	msg, err := jsonrpc.DecodeMessage(body)
	if err != nil {
		http.Error(w, "malformed JSON-RPC message", http.StatusBadRequest)
		return
	}
	sess, created, status, err := s.sessionFor(r, agent, msg)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	req, isReq := msg.(*jsonrpc.Request)
	if !isReq || !req.ID.IsValid() {
		sess.dispatchOneWay(r.Context(), msg)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	resp, err := sess.roundTrip(r.Context(), req)
	if err != nil {
		if created {
			s.closeSession(sess.id)
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	data, err := jsonrpc.EncodeMessage(resp)
	if err != nil {
		http.Error(w, "encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(headerSessionID, sess.id)
	_, _ = w.Write(data)
}

// sessionFor returns the session for a request, creating one on initialize.
func (s *HTTPServer) sessionFor(r *http.Request, agent identity.Agent, msg jsonrpc.Message) (*httpSession, bool, int, error) {
	sid := r.Header.Get(headerSessionID)
	if sid == "" {
		req, ok := msg.(*jsonrpc.Request)
		if !ok || req.Method != "initialize" || !req.ID.IsValid() {
			return nil, false, http.StatusBadRequest, errors.New("missing Mcp-Session-Id (only initialize may start a session)")
		}
		sess, err := s.newSession(agent)
		if errors.Is(err, errSessionLimit) {
			s.log.Warn("session limit reached", "agent", agent.Name)
			return nil, false, http.StatusTooManyRequests, err
		}
		if err != nil {
			s.log.Error("could not start session", "agent", agent.Name, "err", err)
			return nil, false, http.StatusServiceUnavailable, errors.New("could not start upstream session")
		}
		return sess, true, 0, nil
	}
	s.mu.Lock()
	sess := s.sessions[sid]
	s.mu.Unlock()
	// A session is bound to the agent that created it; another token cannot
	// ride on it. Report "not found" either way so ids are not probeable.
	if sess == nil || sess.agent.Name != agent.Name {
		return nil, false, http.StatusNotFound, errors.New("unknown session")
	}
	return sess, false, 0, nil
}

// errSessionLimit means a new session would exceed a configured cap.
var errSessionLimit = errors.New("too many sessions; end one (DELETE) or wait for idle sessions to expire")

// reserve claims a session slot for agent before its upstream is started.
func (s *HTTPServer) reserve(agent string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	total, mine := len(s.sessions), s.starting[agent]
	for _, n := range s.starting {
		total += n
	}
	for _, sess := range s.sessions {
		if sess.agent.Name == agent {
			mine++
		}
	}
	if total >= s.opts.MaxSessions || mine >= s.opts.MaxSessionsPerAgent {
		return false
	}
	s.starting[agent]++
	return true
}

func (s *HTTPServer) unreserve(agent string) {
	s.starting[agent]--
	if s.starting[agent] <= 0 {
		delete(s.starting, agent)
	}
}

func (s *HTTPServer) newSession(agent identity.Agent) (*httpSession, error) {
	if !s.reserve(agent.Name) {
		return nil, errSessionLimit
	}
	id := rand.Text()
	ctx, cancel := context.WithCancel(context.Background())
	b, err := s.opts.NewBackend(ctx, agent, id)
	if err != nil {
		cancel()
		s.mu.Lock()
		s.unreserve(agent.Name)
		s.mu.Unlock()
		return nil, err
	}
	sess := &httpSession{
		id: id, agent: agent, backend: b, ctx: ctx, cancel: cancel, log: s.log.With("session", id[:8], "agent", agent.Name),
		waiters: map[string]chan *jsonrpc.Response{},
	}
	sess.touch()
	s.mu.Lock()
	s.unreserve(agent.Name)
	s.sessions[id] = sess
	s.mu.Unlock()
	go func() {
		sess.readUpstream()
		s.closeSession(id)
	}()
	s.log.Info("session started", "session", id[:8], "agent", agent.Name)
	return sess, nil
}

func (s *HTTPServer) serveDELETE(w http.ResponseWriter, r *http.Request, agent identity.Agent) {
	sid := r.Header.Get(headerSessionID)
	s.mu.Lock()
	sess := s.sessions[sid]
	s.mu.Unlock()
	if sess == nil || sess.agent.Name != agent.Name {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}
	s.closeSession(sid)
	w.WriteHeader(http.StatusNoContent)
}

func (s *HTTPServer) closeSession(id string) {
	s.mu.Lock()
	sess := s.sessions[id]
	delete(s.sessions, id)
	s.mu.Unlock()
	if sess != nil {
		sess.close()
		s.log.Info("session closed", "session", id[:8])
	}
}

// Close ends every session.
func (s *HTTPServer) Close() {
	s.stopOnce.Do(func() { close(s.stop) })
	s.mu.Lock()
	ids := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		s.closeSession(id)
	}
}

func (s *HTTPServer) reap() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
		}
		s.mu.Lock()
		var idle []string
		for id, sess := range s.sessions {
			if sess.idleFor() > s.opts.IdleTimeout {
				idle = append(idle, id)
			}
		}
		s.mu.Unlock()
		for _, id := range idle {
			s.closeSession(id)
		}
	}
}

// originAllowed blocks cross-site browser requests (DNS rebinding). Requests
// without an Origin header (non-browser clients) are allowed; loopback
// origins are allowed; anything else must be listed.
func (s *HTTPServer) originAllowed(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	if slices.Contains(s.opts.AllowedOrigins, o) {
		return true
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// String reports the number of open sessions (for logs).
func (s *HTTPServer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprintf("tollgate http server (%d sessions)", len(s.sessions))
}
