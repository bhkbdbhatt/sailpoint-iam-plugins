package api

import (
	"testing"
	"time"
)

func TestLoginGuardWithinLimit(t *testing.T) {
	g := newLoginGuard(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !g.allow("key") {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
	if g.allow("key") {
		t.Fatal("attempt beyond limit allowed")
	}
	// Different key unaffected.
	if !g.allow("other") {
		t.Fatal("other key should be allowed")
	}
}

func TestLoginGuardReset(t *testing.T) {
	g := newLoginGuard(2, time.Minute)
	g.allow("email:x")
	g.allow("email:x")
	if g.allow("email:x") {
		t.Fatal("limit reached")
	}
	g.reset("email:x")
	if !g.allow("email:x") {
		t.Fatal("reset should clear history")
	}
}

func TestLoginGuardWindowExpiry(t *testing.T) {
	g := newLoginGuard(2, 30*time.Millisecond)
	g.allow("k")
	g.allow("k")
	if g.allow("k") {
		t.Fatal("limit reached within window")
	}
	time.Sleep(40 * time.Millisecond)
	if !g.allow("k") {
		t.Fatal("window should have expired")
	}
}

func TestLoginGuardMapPurge(t *testing.T) {
	g := newLoginGuard(1, time.Nanosecond)
	for i := 0; i < 20_000; i++ {
		g.allow(string(rune('a'+i%26)) + "key" + string(rune('0'+i%10)))
	}
	// No deadlock and no panic on repeated access.
	g.mu.Lock()
	n := len(g.hits)
	g.mu.Unlock()
	if n > 10_000 {
		t.Fatalf("map was not purged: %d", n)
	}
}
