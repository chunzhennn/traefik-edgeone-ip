package traefik_edgeone_ip

import (
	"testing"
	"time"
)

func TestLRUCache_Expiration(t *testing.T) {
	now := time.Date(2025, 12, 30, 0, 0, 0, 0, time.UTC)
	c := newLRUCache(10, time.Second)
	c.now = func() time.Time { return now }

	c.Add("k", true)
	if got, ok := c.Get("k"); !ok || got != true {
		t.Fatalf("expected cached value, got ok=%v val=%v", ok, got)
	}

	now = now.Add(2 * time.Second)
	if _, ok := c.Get("k"); ok {
		t.Fatalf("expected entry to expire")
	}
}

func TestLRUCache_Eviction(t *testing.T) {
	c := newLRUCache(2, time.Hour)

	c.Add("a", true)
	c.Add("b", true)
	c.Add("c", true) // evicts a

	if _, ok := c.Get("a"); ok {
		t.Fatalf("expected 'a' to be evicted")
	}
	if _, ok := c.Get("b"); !ok {
		t.Fatalf("expected 'b' to remain")
	}
	if _, ok := c.Get("c"); !ok {
		t.Fatalf("expected 'c' to remain")
	}
}
