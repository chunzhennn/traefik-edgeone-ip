package traefik_edgeone_ip

import (
	"container/list"
	"sync"
	"time"
)

type lruCacheEntry struct {
	key       string
	value     bool
	expiresAt time.Time
}

// lruCache is a minimal LRU cache with a fixed TTL for all entries.
// It is intentionally non-generic to keep compatibility broad.
type lruCache struct {
	mu sync.Mutex

	maxEntries int
	ttl        time.Duration

	ll    *list.List
	items map[string]*list.Element

	now func() time.Time
}

func newLRUCache(maxEntries int, ttl time.Duration) *lruCache {
	if maxEntries <= 0 {
		maxEntries = 1000
	}
	if ttl <= 0 {
		ttl = time.Hour
	}

	return &lruCache{
		maxEntries: maxEntries,
		ttl:        ttl,
		ll:         list.New(),
		items:      make(map[string]*list.Element, maxEntries),
		now:        time.Now,
	}
}

func (c *lruCache) Get(key string) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ele, ok := c.items[key]
	if !ok {
		return false, false
	}

	entry := ele.Value.(*lruCacheEntry)
	if c.now().After(entry.expiresAt) {
		c.removeElement(ele)
		return false, false
	}

	c.ll.MoveToFront(ele)
	return entry.value, true
}

func (c *lruCache) Add(key string, value bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ele, ok := c.items[key]; ok {
		entry := ele.Value.(*lruCacheEntry)
		entry.value = value
		entry.expiresAt = c.now().Add(c.ttl)
		c.ll.MoveToFront(ele)
		return
	}

	entry := &lruCacheEntry{
		key:       key,
		value:     value,
		expiresAt: c.now().Add(c.ttl),
	}
	ele := c.ll.PushFront(entry)
	c.items[key] = ele

	if c.ll.Len() > c.maxEntries {
		c.removeOldest()
	}
}

func (c *lruCache) removeOldest() {
	ele := c.ll.Back()
	if ele == nil {
		return
	}
	c.removeElement(ele)
}

func (c *lruCache) removeElement(ele *list.Element) {
	c.ll.Remove(ele)
	entry := ele.Value.(*lruCacheEntry)
	delete(c.items, entry.key)
}
