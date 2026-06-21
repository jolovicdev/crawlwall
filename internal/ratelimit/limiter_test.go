package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

func TestLimiterAllowsBurstThenDeniesUntilRefill(t *testing.T) {
	l := New()
	base := time.Unix(1000, 0)
	rpm := 5

	for i := 0; i < rpm; i++ {
		if !l.allowAt("bot.id", rpm, base) {
			t.Fatalf("request %d within burst should be allowed", i)
		}
	}
	if l.allowAt("bot.id", rpm, base) {
		t.Fatalf("request beyond the burst should be denied at the same instant")
	}

	interval := time.Minute / time.Duration(rpm)
	if !l.allowAt("bot.id", rpm, base.Add(interval)) {
		t.Fatalf("one token should refill after a single interval")
	}
}

func TestLimiterZeroRPMAlwaysAllows(t *testing.T) {
	l := New()
	base := time.Unix(1000, 0)
	for i := 0; i < 1000; i++ {
		if !l.allowAt("bot.id", 0, base) {
			t.Fatalf("rpm <= 0 should always allow")
		}
	}
}

func TestLimiterEvictsOldestWhenOverCapacity(t *testing.T) {
	l := New()
	l.maxEntries = 3
	base := time.Unix(1000, 0)

	for i := 0; i < 4; i++ {
		l.allowAt(fmt.Sprintf("ip-%d", i), 10, base.Add(time.Duration(i)*time.Second))
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) > 3 {
		t.Fatalf("entries = %d, want <= 3", len(l.entries))
	}
	if _, ok := l.entries["ip-0"]; ok {
		t.Fatalf("least recently used key ip-0 should have been evicted")
	}
}

func TestLimiterEvictsIdleEntriesPastTTL(t *testing.T) {
	l := New()
	l.maxEntries = 2
	l.ttl = time.Minute
	base := time.Unix(1000, 0)

	l.allowAt("old", 10, base)
	l.allowAt("recent", 10, base.Add(50*time.Second))
	// A third key arrives after old's TTL has elapsed but within recent's.
	l.allowAt("new", 10, base.Add(90*time.Second))

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.entries["old"]; ok {
		t.Fatalf("idle key past TTL should be evicted")
	}
	if _, ok := l.entries["recent"]; !ok {
		t.Fatalf("recent key within TTL should be retained")
	}
	if _, ok := l.entries["new"]; !ok {
		t.Fatalf("new key should be retained")
	}
}

func TestLimiterBlankKeyMapsToGlobalBucket(t *testing.T) {
	l := New()
	base := time.Unix(1000, 0)
	rpm := 1

	if !l.allowAt("", rpm, base) {
		t.Fatalf("first global request should be allowed")
	}
	if l.allowAt("   ", rpm, base) {
		t.Fatalf("a blank key should reuse the global bucket and be denied")
	}
}
