// Package cache defines a provider-agnostic cache contract together with its
// implementations. Consumers depend on the Cache interface so that the backing
// provider (ristretto, otter, in-memory, ...) can be swapped without touching
// call sites.
package cache

import "time"

// Cache is a generic, thread-safe key/value cache contract.
type Cache[K comparable, V any] interface {

	// Get returns the value stored for key and whether it was found.
	Get(key K) (V, bool)

	// Set stores value under key with the given cost. It returns false if the
	// entry was rejected by the admission policy.
	Set(key K, value V, cost int64) bool

	// SetWithTTL stores value with a time-to-live. It returns false if the
	// entry was rejected by the admission policy.
	SetWithTTL(key K, value V, cost int64, ttl time.Duration) bool

	// Del removes a key.
	Del(key K)

	// Wait blocks until pending asynchronous writes have been applied. It is a
	// no-op for synchronous implementations.
	Wait()

	// Close releases resources held by the cache.
	Close()
}
