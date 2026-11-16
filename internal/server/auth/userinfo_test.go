package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/calypr/funnel/api/config"
	"github.com/calypr/funnel/internal/identity"
)

// userinfoFixture serves a JWKS and a scripted userinfo endpoint.
type userinfoFixture struct {
	key    *rsa.PrivateKey
	config *OidcConfig
	calls  atomic.Int32
	answer atomic.Value // func(http.ResponseWriter)
}

func newUserinfoFixture(t *testing.T) *userinfoFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &userinfoFixture{key: key}
	f.respond("application/json", `{"sub": "alice", "groups": ["g1"], "both": "userinfo"}`, 0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			if err := json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA", "use": "sig", "kid": "test-key", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}}); err != nil {
				t.Error(err)
			}
			return
		}
		if r.Header.Get("Authorization") == "" {
			t.Error("userinfo called without the access token")
		}
		f.calls.Add(1)
		f.answer.Load().(func(http.ResponseWriter))(w)
	}))
	t.Cleanup(srv.Close)
	client := &http.Client{Timeout: 300 * time.Millisecond}
	cache, err := newJWKSCacheWithInterval(context.Background(), srv.URL+"/jwks", time.Hour, client)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cache.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})
	f.config = &OidcConfig{
		local:    &config.OidcAuth{RequireAudience: "funnel"},
		remote:   OidcRemoteConfig{Issuer: "https://issuer.example", JwksURI: srv.URL + "/jwks", UserinfoEndpoint: srv.URL + "/userinfo"},
		jwks:     cache,
		client:   client,
		userinfo: newUserinfoCache(2),
	}
	return f
}

func (f *userinfoFixture) respond(contentType, body string, delay time.Duration) {
	f.answer.Store(func(w http.ResponseWriter) {
		time.Sleep(delay)
		w.Header().Set("Content-Type", contentType)
		if _, err := fmt.Fprint(w, body); err != nil {
			panic(err)
		}
	})
}

func (f *userinfoFixture) token(t *testing.T, sub string) string {
	t.Helper()
	return "Bearer " + signOIDCTestToken(t, f.key, map[string]any{
		"iss": "https://issuer.example", "sub": sub, "aud": "funnel", "both": "token", "jti": fmt.Sprint(time.Now().UnixNano()),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
}

func TestAuthorizeAddsUserinfoClaimsAndCachesThem(t *testing.T) {
	f := newUserinfoFixture(t)
	token := f.token(t, "alice")
	for range 2 {
		user := f.config.Authorize(token)
		if user == nil || user.Userinfo == nil {
			t.Fatalf("Authorize() = %+v, want userinfo claims", user)
		}
		if got := *user.Userinfo; fmt.Sprint(got["groups"]) != "[g1]" || (*user.Claims)["both"] != "token" {
			t.Fatalf("claims: token %v, userinfo %v", *user.Claims, got)
		}
	}
	// Case 21: one userinfo call for one token.
	if got := f.calls.Load(); got != 1 {
		t.Fatalf("userinfo calls = %d, want 1", got)
	}
	// The cache is bounded: two more tokens evict the first one.
	f.config.Authorize(f.token(t, "alice"))
	f.config.Authorize(f.token(t, "alice"))
	f.config.Authorize(token)
	if got := f.calls.Load(); got != 4 {
		t.Fatalf("userinfo calls = %d, want 4 after eviction", got)
	}
}

func TestUserinfoCacheExpiry(t *testing.T) {
	cache := newUserinfoCache(2)
	key := [32]byte{1}
	cache.put(key, identity.Claims{"sub": "alice"}, time.Now().Add(-time.Second))
	if _, ok := cache.get(key); ok {
		t.Fatal("get() returned an expired entry")
	}
	if cache.order.Len() != 0 || len(cache.entries) != 0 {
		t.Fatal("expired entry was not removed")
	}
}

func TestAuthorizeCachesUserinfoNoLongerThanTheToken(t *testing.T) {
	// Entries live min(exp, 5 min).
	f := newUserinfoFixture(t)
	exp := time.Now().Add(30 * time.Second).Truncate(time.Second)
	token := "Bearer " + signOIDCTestToken(t, f.key, map[string]any{
		"iss": "https://issuer.example", "sub": "alice", "aud": "funnel", "exp": exp.Unix(),
	})
	f.config.Authorize(token)
	f.config.Authorize(token)
	if got := f.calls.Load(); got != 1 {
		t.Fatalf("userinfo calls = %d, want 1 while cached", got)
	}
	for _, element := range f.config.userinfo.entries {
		if expires := element.Value.(*userinfoEntry).expires; expires.After(exp.Add(time.Millisecond)) {
			t.Fatalf("cache expiry %v is after token exp %v", expires, exp)
		}
	}
}

func TestAuthorizeRejectsUserinfoFailures(t *testing.T) {
	// Case 20: userinfo sub differs, endpoint down, application/jwt, slow.
	for _, tt := range []struct {
		name, contentType, body string
		delay                   time.Duration
	}{
		{"sub differs", "application/json", `{"sub": "mallory"}`, 0},
		{"sub missing", "application/json", `{"groups": ["g1"]}`, 0},
		{"signed userinfo", "application/jwt", `eyJ.eyJ.sig`, 0},
		{"not an object", "application/json", `["sub"]`, 0},
		{"not JSON", "application/json", `{`, 0},
		{"timeout", "application/json", `{"sub": "alice"}`, time.Second},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newUserinfoFixture(t)
			f.respond(tt.contentType, tt.body, tt.delay)
			if user := f.config.Authorize(f.token(t, "alice")); user != nil {
				t.Fatalf("Authorize() = %+v, want nil (401)", user)
			}
		})
	}
	t.Run("error status", func(t *testing.T) {
		f := newUserinfoFixture(t)
		f.answer.Store(func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) })
		if user := f.config.Authorize(f.token(t, "alice")); user != nil {
			t.Fatalf("Authorize() = %+v, want nil (401)", user)
		}
	})
}

func TestAuthorizeWithoutUserinfoMakesNoCall(t *testing.T) {
	f := newUserinfoFixture(t)
	f.config.userinfo = nil
	if user := f.config.Authorize(f.token(t, "alice")); user == nil || user.Userinfo != nil {
		t.Fatalf("Authorize() = %+v, want token claims only", user)
	}
	if got := f.calls.Load(); got != 0 {
		t.Fatalf("userinfo calls = %d, want 0", got)
	}
}
