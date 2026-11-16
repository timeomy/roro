package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/timeomy/tollgate/internal/identity"
)

// errSessionClosed is returned to requests waiting on a closed session.
var errSessionClosed = errors.New("upstream session closed")

// httpSession is one MCP session over HTTP with its own upstream.
type httpSession struct {
	id      string
	agent   identity.Agent
	backend *Backend
	ctx     context.Context
	cancel  context.CancelFunc
	log     *slog.Logger

	lastUsed atomic.Int64

	mu      sync.Mutex
	waiters map[string]chan *jsonrpc.Response
	closed  bool
	once    sync.Once
}

func (s *httpSession) touch()                 { s.lastUsed.Store(time.Now().UnixNano()) }
func (s *httpSession) idleFor() time.Duration { return time.Since(time.Unix(0, s.lastUsed.Load())) }

// roundTrip handles a client request and waits for its response.
func (s *httpSession) roundTrip(reqCtx context.Context, req *jsonrpc.Request) (*jsonrpc.Response, error) {
	s.touch()
	ctx, cancel := mergeDone(reqCtx, s.ctx)
	defer cancel()

	up, down := s.backend.Interceptor.FromClient(ctx, req)
	if down != nil {
		if resp, ok := down.(*jsonrpc.Response); ok {
			return resp, nil
		}
		return nil, errors.New("interceptor answered a request with a non-response")
	}
	if up == nil {
		return nil, errors.New("request dropped")
	}
	key := idKey(req.ID)
	ch := make(chan *jsonrpc.Response, 1)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errSessionClosed
	}
	s.waiters[key] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.waiters, key)
		s.mu.Unlock()
	}()

	if err := s.backend.Upstream.Write(ctx, up); err != nil {
		return nil, errors.New("upstream write failed")
	}
	select {
	case resp, ok := <-ch:
		if !ok {
			return nil, errSessionClosed
		}
		return resp, nil
	case <-ctx.Done():
		s.cancelUpstream(req.ID)
		return nil, errors.New("request cancelled")
	}
}

// dispatchOneWay forwards a notification or a client response.
func (s *httpSession) dispatchOneWay(reqCtx context.Context, msg jsonrpc.Message) {
	s.touch()
	up, _ := s.backend.Interceptor.FromClient(reqCtx, msg)
	if up != nil {
		if err := s.backend.Upstream.Write(s.ctx, up); err != nil {
			s.log.Debug("upstream write failed", "err", err)
		}
	}
}

// cancelUpstream tells the upstream the client gave up on a request.
func (s *httpSession) cancelUpstream(id jsonrpc.ID) {
	params, _ := json.Marshal(map[string]any{"requestId": id.Raw(), "reason": "client disconnected"})
	_ = s.backend.Upstream.Write(s.ctx, &jsonrpc.Request{Method: "notifications/cancelled", Params: params})
}

// readUpstream delivers upstream responses to waiting requests until the
// upstream closes.
func (s *httpSession) readUpstream() {
	for {
		msg, err := s.backend.Upstream.Read(s.ctx)
		if err != nil {
			s.log.Debug("upstream closed", "err", err)
			return
		}
		switch m := msg.(type) {
		case *jsonrpc.Response:
			out, ok := s.backend.Interceptor.FromUpstream(s.ctx, m).(*jsonrpc.Response)
			if !ok || out == nil {
				continue
			}
			// Deliver under the lock so close() cannot close ch mid-send.
			// Each waiter's channel has room for its one response.
			s.mu.Lock()
			if ch := s.waiters[idKey(out.ID)]; ch != nil {
				select {
				case ch <- out:
				default:
				}
			}
			s.mu.Unlock()
		case *jsonrpc.Request:
			s.answerServerRequest(m)
		}
	}
}

// answerServerRequest replies to upstream-initiated requests, which this
// transport cannot carry to the client (no GET stream). Ping is answered so
// keep-alives work; notifications are dropped.
func (s *httpSession) answerServerRequest(req *jsonrpc.Request) {
	if !req.ID.IsValid() {
		s.log.Debug("dropping upstream notification", "method", req.Method)
		return
	}
	resp := &jsonrpc.Response{ID: req.ID}
	if req.Method == "ping" {
		resp.Result = json.RawMessage(`{}`)
	} else {
		resp.Error = &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound,
			Message: "tollgate HTTP mode does not relay server-initiated requests (" + req.Method + ")"}
	}
	_ = s.backend.Upstream.Write(s.ctx, resp)
}

func (s *httpSession) close() {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		for k, ch := range s.waiters {
			close(ch)
			delete(s.waiters, k)
		}
		s.mu.Unlock()
		s.cancel()
		s.backend.Interceptor.Close()
		_ = s.backend.Upstream.Close()
		if s.backend.Stop != nil {
			_ = s.backend.Stop()
		}
	})
}

// mergeDone returns a context cancelled when either parent is done.
func mergeDone(a, b context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(a)
	stop := context.AfterFunc(b, cancel)
	return ctx, func() { stop(); cancel() }
}
