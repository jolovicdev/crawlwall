package lru

import (
	"fmt"
	"testing"
	"time"
)

func TestTrimReclaimsABatchOfTheLeastRecentlyUsed(t *testing.T) {
	const maxEntries = 64
	base := time.Now()

	items := map[string]time.Time{}
	for i := 0; i < maxEntries+1; i++ {
		items[fmt.Sprintf("key-%03d", i)] = base.Add(time.Duration(i) * time.Second)
	}

	Trim(items, maxEntries, func(access time.Time) time.Time { return access })

	target := maxEntries - maxEntries/headroomDivisor
	if len(items) != target {
		t.Fatalf("len(items) = %d, want the low-water mark %d", len(items), target)
	}
	// The survivors must be the most recently used entries.
	for i := maxEntries + 1 - target; i <= maxEntries; i++ {
		if _, ok := items[fmt.Sprintf("key-%03d", i)]; !ok {
			t.Fatalf("recently used key-%03d was evicted", i)
		}
	}
}

func TestTrimLeavesRoomUnderTheCapAlone(t *testing.T) {
	items := map[string]time.Time{"a": time.Now()}
	Trim(items, 64, func(access time.Time) time.Time { return access })
	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1: nothing to reclaim below the cap", len(items))
	}
}
