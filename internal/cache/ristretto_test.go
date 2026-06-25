package cache

import (
	"testing"
	"time"
)

func newTestCache[V any](t *testing.T) Cache[string, V] {
	t.Helper()
	c, err := NewRistretto[V](RistrettoConfig{
		NumCounters: 1000,
		MaxCost:     100,
		BufferItems: 64,
	})
	if err != nil {
		t.Fatalf("NewRistretto: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestRistretto_SetGet(t *testing.T) {
	c := newTestCache[int](t)

	if !c.Set("a", 42, 1) {
		// Admission may rarely reject; not a hard failure, but Wait+Get should
		// still reflect a successful set in the common case.
		t.Log("Set returned false (admission rejected)")
	}
	c.Wait()

	got, ok := c.Get("a")
	if !ok {
		t.Fatalf("expected hit for key 'a' after Wait")
	}
	if got != 42 {
		t.Fatalf("got %d, want 42", got)
	}
}

func TestRistretto_GetMiss(t *testing.T) {
	c := newTestCache[int](t)

	if _, ok := c.Get("missing"); ok {
		t.Fatalf("expected miss for absent key")
	}
}

func TestRistretto_SetWithTTLExpires(t *testing.T) {
	c := newTestCache[string](t)

	c.SetWithTTL("k", "v", 1, 50*time.Millisecond)
	c.Wait()

	if _, ok := c.Get("k"); !ok {
		t.Fatalf("expected hit immediately after SetWithTTL+Wait")
	}

	time.Sleep(150 * time.Millisecond)

	if _, ok := c.Get("k"); ok {
		t.Fatalf("expected miss after TTL expiry")
	}
}

func TestRistretto_Del(t *testing.T) {
	c := newTestCache[int](t)

	c.Set("d", 7, 1)
	c.Wait()
	c.Del("d")
	c.Wait()

	if _, ok := c.Get("d"); ok {
		t.Fatalf("expected miss after Del")
	}
}

func TestRistretto_PointerValue(t *testing.T) {
	c := newTestCache[*int](t)

	v := 99
	c.Set("p", &v, 1)
	c.Wait()

	got, ok := c.Get("p")
	if !ok {
		t.Fatalf("expected hit for pointer value")
	}
	if got != &v {
		t.Fatalf("expected same pointer back")
	}
}
