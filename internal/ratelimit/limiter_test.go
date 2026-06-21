package ratelimit

import (
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
