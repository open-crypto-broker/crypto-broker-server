package cache

import (
	"time"

	"github.com/dgraph-io/ristretto/v2"
)

// Compile-time check that ristrettoCache satisfies the Cache contract.
var _ Cache[string, any] = (*ristrettoCache[any])(nil)

// RistrettoConfig holds tuning parameters for the ristretto-backed cache.
type RistrettoConfig struct {

	// NumCounters is the number of keys to track frequency of. A good default is
	// roughly 10x the maximum number of entries the cache will hold.
	NumCounters int64

	// MaxCost is the capacity budget. With a per-entry cost of 1 it equals the
	// maximum number of entries.
	MaxCost int64

	// BufferItems is the size of the Get buffers. 64 is a sensible default.
	BufferItems int64
}

// ristrettoCache adapts *ristretto.Cache to the Cache interface. Keys are fixed
// to string, which is what every current consumer uses and which satisfies both
// the comparable constraint of Cache and ristretto's key constraint.
type ristrettoCache[V any] struct {
	c *ristretto.Cache[string, V]
}

// DefaultRistrettoConfig is a general-purpose configuration suitable for small
// caches holding up to a few thousand entries. It is intended for tests,
// benchmarks and callers without specific sizing requirements.
var DefaultRistrettoConfig = RistrettoConfig{
	NumCounters: 10_000,
	MaxCost:     1_000,
	BufferItems: 64,
}

// MustNewRistretto is like NewRistretto but panics on configuration errors.
// Convenient for tests, benchmarks and wiring where a misconfiguration is a
// programming error rather than a runtime condition.
func MustNewRistretto[V any](cfg RistrettoConfig) Cache[string, V] {
	c, err := NewRistretto[V](cfg)
	if err != nil {
		panic(err)
	}

	return c
}

// NewRistretto builds a string-keyed ristretto cache satisfying Cache[string, V].
func NewRistretto[V any](cfg RistrettoConfig) (Cache[string, V], error) {
	c, err := ristretto.NewCache(&ristretto.Config[string, V]{
		NumCounters: cfg.NumCounters,
		MaxCost:     cfg.MaxCost,
		BufferItems: cfg.BufferItems,
	})
	if err != nil {
		return nil, err
	}

	return &ristrettoCache[V]{c: c}, nil
}

func (r *ristrettoCache[V]) Get(key string) (V, bool) {
	return r.c.Get(key)
}

func (r *ristrettoCache[V]) Set(key string, value V, cost int64) bool {
	return r.c.Set(key, value, cost)
}

func (r *ristrettoCache[V]) SetWithTTL(key string, value V, cost int64, ttl time.Duration) bool {
	return r.c.SetWithTTL(key, value, cost, ttl)
}

func (r *ristrettoCache[V]) Del(key string) {
	r.c.Del(key)
}

func (r *ristrettoCache[V]) Wait() {
	r.c.Wait()
}

func (r *ristrettoCache[V]) Close() {
	r.c.Close()
}
