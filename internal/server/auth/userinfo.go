package auth

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"

	"github.com/calypr/funnel/internal/identity"
)

const (
	userinfoCacheSize = 1024
	userinfoMaxAge    = 5 * time.Minute
)

// lookupUserinfo returns the userinfo claims for a validated token, from
// the cache or the userinfo endpoint. Any failure, a non-JSON answer
// (signed or encrypted userinfo) or a different sub rejects the token.
func (c *OidcConfig) lookupUserinfo(token, subject string, claims identity.Claims) (identity.Claims, bool) {
	key := sha256.Sum256([]byte(token))
	if cached, ok := c.userinfo.get(key); ok {
		return cached, true
	}
	request, err := http.NewRequest(http.MethodGet, c.remote.UserinfoEndpoint, nil)
	if err != nil {
		return nil, false
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		fmt.Printf("[WARN] Userinfo request failed: %s\n", err)
		return nil, false
	}
	defer response.Body.Close() //nolint:errcheck // Read-only response cleanup cannot change the result.
	mediaType, _, typeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil || typeErr != nil || response.StatusCode != http.StatusOK || mediaType != "application/json" {
		fmt.Printf("[WARN] Userinfo answered %d (%s); token rejected\n", response.StatusCode, mediaType)
		return nil, false
	}
	var userinfo identity.Claims
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if decoder.Decode(&userinfo) != nil || userinfo["sub"] != subject {
		fmt.Println("[WARN] Userinfo is not a JSON object with the token's sub; token rejected")
		return nil, false
	}
	ttl := userinfoMaxAge
	if number, ok := claims["exp"].(json.Number); ok {
		if exp, err := number.Int64(); err == nil && time.Until(time.Unix(exp, 0)) < ttl {
			ttl = time.Until(time.Unix(exp, 0))
		}
	}
	c.userinfo.put(key, userinfo, time.Now().Add(ttl))
	return userinfo, true
}

// userinfoCache is a bounded LRU cache of userinfo answers, keyed by a
// hash of the token, with an expiry per entry.
type userinfoCache struct {
	mu      sync.Mutex
	size    int
	order   *list.List
	entries map[[32]byte]*list.Element
}

type userinfoEntry struct {
	key     [32]byte
	claims  identity.Claims
	expires time.Time
}

func newUserinfoCache(size int) *userinfoCache {
	return &userinfoCache{size: size, order: list.New(), entries: map[[32]byte]*list.Element{}}
}

func (c *userinfoCache) get(key [32]byte) (identity.Claims, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	element, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	entry := element.Value.(*userinfoEntry)
	if time.Now().After(entry.expires) {
		c.order.Remove(element)
		delete(c.entries, key)
		return nil, false
	}
	c.order.MoveToFront(element)
	return entry.claims, true
}

func (c *userinfoCache) put(key [32]byte, claims identity.Claims, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if element, ok := c.entries[key]; ok {
		c.order.Remove(element)
	}
	c.entries[key] = c.order.PushFront(&userinfoEntry{key, claims, expires})
	if c.order.Len() > c.size {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*userinfoEntry).key)
	}
}
