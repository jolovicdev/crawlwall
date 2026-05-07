package ratelimit

import (
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type Limiter struct {
	mu      sync.Mutex
	entries map[string]*rate.Limiter
}

func New() *Limiter {
	return &Limiter{
		entries: make(map[string]*rate.Limiter),
	}
}

func (l *Limiter) Allow(key string, rpm int) bool {
	if rpm <= 0 {
		return true
	}

	if strings.TrimSpace(key) == "" {
		key = "global"
	}

	l.mu.Lock()
	limiter, ok := l.entries[key]
	if !ok {
		interval := time.Minute / time.Duration(rpm)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		limiter = rate.NewLimiter(rate.Every(interval), rpm)
		l.entries[key] = limiter
	}
	l.mu.Unlock()

	return limiter.Allow()
}
