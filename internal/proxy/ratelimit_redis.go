package proxy

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisRateStore is a distributed sliding-window limiter backed by Redis.
//
// The sliding-window algorithm is implemented server-side as a Lua script so
// each Allow() is a single round trip and the check+increment is atomic
// (Redis evaluates scripts single-threaded). This matters when many proxy
// replicas hit the same limit concurrently — doing it client-side would
// race under load.
//
// Keyspace: "oktsec:rl:<key>" (sorted set of timestamps, trimmed to window).
// Each value is the request timestamp; cardinality IS the count.
type RedisRateStore struct {
	client *redis.Client
	limit  int
	window time.Duration
	logger *slog.Logger
	prefix string
}

// allowScript: sliding-window counter in a single ZSET.
//
//  1. ZREMRANGEBYSCORE drops timestamps older than (now - window).
//  2. ZCARD counts what remains.
//  3. If count < limit, ZADD the current timestamp and EXPIRE (so keys
//     vacate themselves even without traffic).
//
// Returns 1 when admitted, 0 when rejected. Keeping the fallback simple
// keeps the script atomic — no branching on Redis errors.
const allowScript = `
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])

redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local count = redis.call('ZCARD', key)
if count < limit then
  redis.call('ZADD', key, now, now .. ':' .. math.random())
  redis.call('PEXPIRE', key, math.ceil(window))
  return 1
end
return 0
`

// NewRedisRateStore dials Redis and returns a limiter ready to use.
// The caller passes an already-configured redis.Client so ops teams can
// supply auth, TLS, cluster endpoints, sentinels etc. without us having
// to surface every redis knob in our own config.
func NewRedisRateStore(client *redis.Client, limit int, window time.Duration, logger *slog.Logger) (*RedisRateStore, error) {
	if client == nil {
		return nil, errors.New("redis client is nil")
	}
	if limit <= 0 {
		return nil, errors.New("limit must be positive")
	}
	if window <= 0 {
		window = time.Minute
	}
	if logger == nil {
		logger = slog.Default()
	}
	// Fail fast on bad config — an unreachable Redis would silently
	// degrade to "everything allowed" (limit unreachable) if we didn't
	// ping at startup.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}
	return &RedisRateStore{
		client: client,
		limit:  limit,
		window: window,
		logger: logger,
		prefix: "oktsec:rl:",
	}, nil
}

// Allow implements RateStore. Fails open on Redis error — dropping traffic
// because the limiter is sick is worse than momentarily over-admitting.
// The error is logged so ops can see the degradation.
func (r *RedisRateStore) Allow(key string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	now := time.Now().UnixMilli()
	windowMs := r.window.Milliseconds()

	res, err := r.client.Eval(ctx, allowScript, []string{r.prefix + key},
		now, windowMs, r.limit).Int()
	if err != nil {
		r.logger.Warn("redis rate limiter error, failing open", "key", key, "error", err)
		return true
	}
	return res == 1
}

// Stop closes the underlying redis client. Safe to call more than once.
func (r *RedisRateStore) Stop() {
	if r.client != nil {
		_ = r.client.Close()
	}
}

// Compile-time check.
var _ RateStore = (*RedisRateStore)(nil)

// redisParseURL is a thin wrapper so callers in this package don't need
// to import go-redis directly. Returns a client configured from a
// `redis://user:pass@host:port/db` URL.
func redisParseURL(raw string) (*redis.Client, error) {
	opts, err := redis.ParseURL(raw)
	if err != nil {
		return nil, err
	}
	return redis.NewClient(opts), nil
}
