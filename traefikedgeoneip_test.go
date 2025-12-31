package traefik_edgeone_ip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
)

type stubValidator struct {
	mu    sync.Mutex
	calls int

	result bool
	err    error
}

func (s *stubValidator) Validate(_ context.Context, _ *netip.Addr) (bool, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return s.result, s.err
}

func (s *stubValidator) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestMiddleware_Untrusted_IgnoresHeaders(t *testing.T) {
	var gotRealIP, gotXFF, gotTrusted string

	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotRealIP = r.Header.Get(HeaderXRealIP)
		gotXFF = r.Header.Get(HeaderXForwardedFor)
		gotTrusted = r.Header.Get(HeaderXForwardedFromEdgeOne)
	})

	v := &stubValidator{result: false}
	m := &EdgeOneIP{
		next:      next,
		name:      "test",
		logger:    NewPluginLogger("test", LogLevelError),
		validator: v,
		cache:     lru.NewLRU[string, bool](100, nil, time.Hour),
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "1.1.1.1:1234"
	req.Header.Set(HeaderXForwardedFor, "8.8.8.8")

	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if gotTrusted != "no" {
		t.Fatalf("expected trusted=no, got %q", gotTrusted)
	}
	if gotRealIP != "1.1.1.1" {
		t.Fatalf("expected X-Real-IP=1.1.1.1, got %q", gotRealIP)
	}
	if gotXFF != "1.1.1.1" {
		t.Fatalf("expected X-Forwarded-For=1.1.1.1, got %q", gotXFF)
	}
}

func TestMiddleware_EdgeOne_SkipsPrivateXRealIP_UsesXFF(t *testing.T) {
	var gotRealIP, gotXFF string

	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotRealIP = r.Header.Get(HeaderXRealIP)
		gotXFF = r.Header.Get(HeaderXForwardedFor)
	})

	v := &stubValidator{result: true}
	m := &EdgeOneIP{
		next:      next,
		name:      "test",
		logger:    NewPluginLogger("test", LogLevelError),
		validator: v,
		cache:     lru.NewLRU[string, bool](100, nil, time.Hour),
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "1.1.1.1:1234"
	req.Header.Set(HeaderXRealIP, "10.0.0.1")
	req.Header.Set(HeaderXForwardedFor, "8.8.8.8, 10.0.0.1")

	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if gotRealIP != "8.8.8.8" {
		t.Fatalf("expected X-Real-IP=8.8.8.8, got %q", gotRealIP)
	}
	if gotXFF != "8.8.8.8, 10.0.0.1, 1.1.1.1" {
		t.Fatalf("expected X-Forwarded-For to keep existing chain and add source IP, got %q", gotXFF)
	}
}

func TestMiddleware_CachesValidationResult(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	v := &stubValidator{result: true}
	m := &EdgeOneIP{
		next:      next,
		name:      "test",
		logger:    NewPluginLogger("test", LogLevelError),
		validator: v,
		cache:     lru.NewLRU[string, bool](100, nil, time.Hour),
	}

	req1 := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req1.RemoteAddr = "1.1.1.1:1234"

	req2 := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req2.RemoteAddr = "1.1.1.1:5678"

	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req1)
	m.ServeHTTP(rr, req2)

	if v.Calls() != 1 {
		t.Fatalf("expected validator to be called once due to caching, got %d", v.Calls())
	}
}

func TestMiddleware_SkipsValidationForPrivateSrcIP(t *testing.T) {
	var gotRealIP, gotXFF, gotTrusted string

	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotRealIP = r.Header.Get(HeaderXRealIP)
		gotXFF = r.Header.Get(HeaderXForwardedFor)
		gotTrusted = r.Header.Get(HeaderXForwardedFromEdgeOne)
	})

	v := &stubValidator{result: true}
	m := &EdgeOneIP{
		next:      next,
		name:      "test",
		logger:    NewPluginLogger("test", LogLevelError),
		validator: v,
		cache:     lru.NewLRU[string, bool](100, nil, time.Hour),
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set(HeaderXRealIP, "8.8.8.8")

	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if v.Calls() != 0 {
		t.Fatalf("expected validator not to be called for private src ip, got %d", v.Calls())
	}
	if gotTrusted != "no" {
		t.Fatalf("expected trusted=no, got %q", gotTrusted)
	}
	if gotRealIP != "10.0.0.1" {
		t.Fatalf("expected X-Real-IP=10.0.0.1, got %q", gotRealIP)
	}
	if gotXFF != "10.0.0.1" {
		t.Fatalf("expected X-Forwarded-For=10.0.0.1, got %q", gotXFF)
	}
}
