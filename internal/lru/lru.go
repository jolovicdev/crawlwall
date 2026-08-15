// Package lru trims bounded maps in batches.
package lru

import (
	"slices"
	"time"
)

// headroomDivisor sets how much headroom one trim reclaims: maxEntries/8
// entries, so the scan cost amortizes over that many subsequent inserts.
const headroomDivisor = 8

// Trim deletes the least recently used entries until items sits a batch of
// headroom under maxEntries. Reclaiming a batch rather than one entry matters
// when a flood of unique keys holds the map at its cap: trimming singly would
// make every insert past the cap pay a full scan, usually under the caller's
// lock. access reports an entry's last use; callers should drop entries that
// are expired outright before trimming by recency.
func Trim[K comparable, V any](items map[K]V, maxEntries int, access func(V) time.Time) {
	surplus := len(items) - (maxEntries - maxEntries/headroomDivisor)
	if surplus <= 0 {
		return
	}

	times := make([]time.Time, 0, len(items))
	for _, value := range items {
		times = append(times, access(value))
	}
	slices.SortFunc(times, func(a, b time.Time) int { return a.Compare(b) })

	cutoff := times[surplus-1]
	for key, value := range items {
		if !access(value).After(cutoff) {
			delete(items, key)
		}
	}
}
