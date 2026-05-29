package valkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// Client wraps a go-redis client plus the configured index SET key. It exposes
// exactly the operations knit needs: publish/read a per-cert value, and
// add/remove/list index members.
type Client struct {
	rdb      *redis.Client
	indexKey string
}

// New parses a Valkey connection string (redis:// or rediss:// for TLS) and
// returns a ready Client. It does not dial; the first operation establishes the
// connection.
func New(url, indexKey string) (*Client, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parse valkey url: %w", err)
	}
	return &Client{rdb: redis.NewClient(opt), indexKey: indexKey}, nil
}

// Close releases the underlying connection pool.
func (c *Client) Close() error { return c.rdb.Close() }

// Ping verifies connectivity.
func (c *Client) Ping(ctx context.Context) error { return c.rdb.Ping(ctx).Err() }

// SetCert serializes v and writes it to key with a single SET.
func (c *Client) SetCert(ctx context.Context, key string, v Value) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal value: %w", err)
	}
	if err := c.rdb.Set(ctx, key, b, 0).Err(); err != nil {
		return fmt.Errorf("set %q: %w", key, err)
	}
	return nil
}

// GetCert reads and deserializes the value at key. The bool is false (with a nil
// error) when the key is absent.
func (c *Client) GetCert(ctx context.Context, key string) (*Value, bool, error) {
	b, err := c.rdb.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("get %q: %w", key, err)
	}
	var v Value
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, false, fmt.Errorf("unmarshal %q: %w", key, err)
	}
	return &v, true, nil
}

// AddToIndex adds key to the index SET.
func (c *Client) AddToIndex(ctx context.Context, key string) error {
	if err := c.rdb.SAdd(ctx, c.indexKey, key).Err(); err != nil {
		return fmt.Errorf("sadd %q: %w", c.indexKey, err)
	}
	return nil
}

// IndexMembers returns the current members of the index SET.
func (c *Client) IndexMembers(ctx context.Context) ([]string, error) {
	members, err := c.rdb.SMembers(ctx, c.indexKey).Result()
	if err != nil {
		return nil, fmt.Errorf("smembers %q: %w", c.indexKey, err)
	}
	return members, nil
}

// Prune removes key from the index SET and deletes the per-cert value. Used when
// a cert is removed or disabled in Postgres.
func (c *Client) Prune(ctx context.Context, key string) error {
	if err := c.rdb.SRem(ctx, c.indexKey, key).Err(); err != nil {
		return fmt.Errorf("srem %q: %w", key, err)
	}
	if err := c.rdb.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("del %q: %w", key, err)
	}
	return nil
}
