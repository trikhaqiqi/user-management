package router

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"godigi/api-gateway/internal/middleware"
	"godigi/api-gateway/internal/proxy"
	"godigi/pkg/httpx"
	"godigi/pkg/jwtx"
)

// TestIdentityHeadersAreGatewayAsserted checks the trust boundary. Whatever
// identity headers the client sends, the upstream service must see only the
// ones derived from the verified token, plus the internal token, and never
// the client's Authorization header.
func TestIdentityHeadersAreGatewayAsserted(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	userID, sessionID := uuid.New(), uuid.New()
	token, _, err := jwtx.NewSigner(priv, time.Minute).Sign(userID, sessionID)
	if err != nil {
		t.Fatal(err)
	}

	var seen http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Header().Set(httpx.HeaderRequestID, "from-upstream")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)

	r := gin.New()
	r.Use(middleware.StripIdentityHeaders(), httpx.RequestID(slog.Default()))
	r.GET("/api/v1/users/me", middleware.Authenticate(jwtx.NewVerifier(pub)),
		proxy.New(target, "internal-secret", time.Second, slog.Default()).Handler())

	gw := httptest.NewServer(r)
	defer gw.Close()
	req, _ := http.NewRequest(http.MethodGet, gw.URL+"/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(httpx.HeaderUserID, uuid.NewString())
	req.Header.Set(httpx.HeaderSessionID, uuid.NewString())
	req.Header.Set(httpx.HeaderInternalToken, "forged")
	req.Header.Set(httpx.HeaderClientIP, "1.2.3.4")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	if got := seen.Get(httpx.HeaderUserID); got != userID.String() {
		t.Errorf("upstream X-User-ID = %q, want token subject", got)
	}
	if got := seen.Get(httpx.HeaderSessionID); got != sessionID.String() {
		t.Errorf("upstream X-Session-ID = %q, want token sid", got)
	}
	if got := seen.Values(httpx.HeaderInternalToken); len(got) != 1 || got[0] != "internal-secret" {
		t.Errorf("upstream internal token = %v", got)
	}
	if got := seen.Get(httpx.HeaderClientIP); got == "1.2.3.4" {
		t.Error("client-supplied X-Client-IP was forwarded")
	}
	if seen.Get("Authorization") != "" {
		t.Error("Authorization header leaked upstream")
	}
	if got := res.Header.Values(httpx.HeaderRequestID); len(got) != 1 || got[0] == "from-upstream" {
		t.Errorf("response X-Request-ID = %v, want exactly the gateway's", got)
	}
}

func TestAuthenticateRejects(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	expired, _, _ := jwtx.NewSigner(priv, -time.Minute).Sign(uuid.New(), uuid.New())

	r := gin.New()
	r.GET("/x", middleware.Authenticate(jwtx.NewVerifier(pub)), func(c *gin.Context) { c.Status(http.StatusOK) })

	for name, tc := range map[string]struct{ header, code string }{
		"missing":   {"", "MISSING_TOKEN"},
		"no scheme": {"abc", "MISSING_TOKEN"},
		"basic":     {"Basic abc", "MISSING_TOKEN"},
		"garbage":   {"Bearer abc.def.ghi", "INVALID_TOKEN"},
		"expired":   {"Bearer " + expired, "TOKEN_EXPIRED"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		body, _ := io.ReadAll(rec.Body)
		var env struct {
			Error struct{ Code string } `json:"error"`
		}
		_ = json.Unmarshal(body, &env)
		if rec.Code != http.StatusUnauthorized || env.Error.Code != tc.code {
			t.Errorf("%s: got %d %s, want 401 %s", name, rec.Code, env.Error.Code, tc.code)
		}
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%s: missing WWW-Authenticate", name)
		}
	}
}
