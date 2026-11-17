package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/timeomy/tollgate/internal/identity"
)

// passInterceptor forwards everything.
type passInterceptor struct{}

func (passInterceptor) FromClient(_ context.Context, m jsonrpc.Message) (jsonrpc.Message, jsonrpc.Message) {
	return m, nil
}
func (passInterceptor) FromUpstream(_ context.Context, m jsonrpc.Message) jsonrpc.Message { return m }
func (passInterceptor) Blocking(jsonrpc.Message) bool                                     { return false }
func (passInterceptor) Close()                                                            {}

func newTestHTTP(t *testing.T, mutate ...func(*HTTPOptions)) *httptest.Server {
	t.Helper()
	opts := HTTPOptions{
		Authenticate: func(r *http.Request) (identity.Agent, bool) {
			switch r.Header.Get("Authorization") {
			case "Bearer alice":
				return identity.Agent{Name: "alice"}, true
			case "Bearer bob":
				return identity.Agent{Name: "bob"}, true
			}
			return identity.Agent{}, false
		},
		NewBackend: func(ctx context.Context, _ identity.Agent, _ string) (*Backend, error) {
			clientSide, serverSide := mcp.NewInMemoryTransports()
			if _, err := newEchoServer().Connect(ctx, serverSide, nil); err != nil {
				return nil, err
			}
			conn, err := clientSide.Connect(ctx)
			if err != nil {
				return nil, err
			}
			return &Backend{Interceptor: passInterceptor{}, Upstream: conn}, nil
		},
	}
	for _, m := range mutate {
		m(&opts)
	}
	hs, err := NewHTTPServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(hs)
	t.Cleanup(func() { hs.Close(); srv.Close() })
	return srv
}

func post(t *testing.T, url, token, session, body string, hdr ...string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if session != "" {
		req.Header.Set(headerSessionID, session)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

const initBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`

func TestHTTPSessionLifecycle(t *testing.T) {
	srv := newTestHTTP(t)
	resp := post(t, srv.URL, "alice", "", initBody)
	sid := resp.Header.Get(headerSessionID)
	if resp.StatusCode != 200 || sid == "" {
		t.Fatalf("initialize: status %d session %q", resp.StatusCode, sid)
	}
	var init struct {
		Result struct {
			ServerInfo struct{ Name string } `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&init); err != nil || init.Result.ServerInfo.Name != "echo" {
		t.Fatalf("initialize body: %+v %v", init, err)
	}
	if r := post(t, srv.URL, "alice", sid, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); r.StatusCode != http.StatusAccepted {
		t.Fatalf("notification status = %d", r.StatusCode)
	}
	call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`
	if r := post(t, srv.URL, "alice", sid, call); r.StatusCode != 200 {
		t.Fatalf("tools/call status = %d", r.StatusCode)
	}

	// Another agent's token cannot use alice's session.
	if r := post(t, srv.URL, "bob", sid, call); r.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-agent status = %d, want 404", r.StatusCode)
	}
	// DELETE ends the session.
	req, _ := http.NewRequest(http.MethodDelete, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer alice")
	req.Header.Set(headerSessionID, sid)
	if r, err := http.DefaultClient.Do(req); err != nil || r.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE: %v %v", r, err)
	}
	if r := post(t, srv.URL, "alice", sid, call); r.StatusCode != http.StatusNotFound {
		t.Fatalf("after DELETE status = %d", r.StatusCode)
	}
}

func TestHTTPRejections(t *testing.T) {
	srv := newTestHTTP(t)
	cases := []struct {
		name   string
		resp   *http.Response
		status int
	}{
		{"no token", post(t, srv.URL, "", "", initBody), http.StatusUnauthorized},
		{"bad token", post(t, srv.URL, "mallory", "", initBody), http.StatusUnauthorized},
		{"foreign origin", post(t, srv.URL, "alice", "", initBody, "Origin", "https://evil.example"), http.StatusForbidden},
		{"no session, not initialize", post(t, srv.URL, "alice", "", `{"jsonrpc":"2.0","id":1,"method":"ping"}`), http.StatusBadRequest},
		{"batch", post(t, srv.URL, "alice", "", "["+initBody+"]"), http.StatusBadRequest},
		{"garbage", post(t, srv.URL, "alice", "", `{nope`), http.StatusBadRequest},
		{"unknown session", post(t, srv.URL, "alice", "nope", `{"jsonrpc":"2.0","id":1,"method":"ping"}`), http.StatusNotFound},
		{"loopback origin ok", post(t, srv.URL, "alice", "", initBody, "Origin", "http://localhost:3000"), http.StatusOK},
	}
	for _, c := range cases {
		if c.resp.StatusCode != c.status {
			t.Errorf("%s: status %d, want %d", c.name, c.resp.StatusCode, c.status)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer alice")
	if r, err := http.DefaultClient.Do(req); err != nil || r.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET: %v %v", r, err)
	}
}

func TestHTTPSessionLimits(t *testing.T) {
	srv := newTestHTTP(t, func(o *HTTPOptions) { o.MaxSessions = 3; o.MaxSessionsPerAgent = 2 })
	for i := range 2 {
		if r := post(t, srv.URL, "alice", "", initBody); r.StatusCode != 200 {
			t.Fatalf("alice session %d: status %d", i, r.StatusCode)
		}
	}
	if r := post(t, srv.URL, "alice", "", initBody); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("alice over per-agent cap: status %d, want 429", r.StatusCode)
	}
	first := post(t, srv.URL, "bob", "", initBody)
	if first.StatusCode != 200 {
		t.Fatalf("bob session: status %d", first.StatusCode)
	}
	if r := post(t, srv.URL, "bob", "", initBody); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("over total cap: status %d, want 429", r.StatusCode)
	}
	// Ending a session frees its slot.
	req, _ := http.NewRequest(http.MethodDelete, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer bob")
	req.Header.Set(headerSessionID, first.Header.Get(headerSessionID))
	if r, err := http.DefaultClient.Do(req); err != nil || r.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE: %v %v", r, err)
	}
	if r := post(t, srv.URL, "bob", "", initBody); r.StatusCode != 200 {
		t.Fatalf("after DELETE: status %d", r.StatusCode)
	}
}
