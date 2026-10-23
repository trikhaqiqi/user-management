// Package proxy forwards requests from the gateway to backend services.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"

	"godigi/pkg/httpx"
)

// gatewayOwned are response headers the gateway sets itself. Upstream copies
// are dropped so clients don't see each one twice.
var gatewayOwned = []string{
	httpx.HeaderRequestID, "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Cache-Control",
}

type Proxy struct {
	rp *httputil.ReverseProxy
}

func New(target *url.URL, internalToken string, timeout time.Duration, log *slog.Logger) *Proxy {
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: timeout,
	}
	rp := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.SetXForwarded()
			// The access token stops here; services get the verified ids.
			r.Out.Header.Del("Authorization")
			r.Out.Header.Del("Cookie")
			r.Out.Header.Set(httpx.HeaderInternalToken, internalToken)
		},
		ModifyResponse: func(res *http.Response) error {
			for _, h := range gatewayOwned {
				res.Header.Del(h)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			status, code, msg := http.StatusBadGateway, "UPSTREAM_UNAVAILABLE", "the upstream service is unavailable"
			if errors.Is(err, context.DeadlineExceeded) {
				status, code, msg = http.StatusGatewayTimeout, "UPSTREAM_TIMEOUT", "the upstream service did not respond in time"
			}
			if errors.Is(err, context.Canceled) {
				return // client went away
			}
			log.Error("proxy error", "upstream", target.Host, "path", r.URL.Path,
				"request_id", r.Header.Get(httpx.HeaderRequestID), "error", err.Error())
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success":    false,
				"error":      map[string]string{"code": code, "message": msg},
				"request_id": r.Header.Get(httpx.HeaderRequestID),
			})
		},
	}
	return &Proxy{rp: rp}
}

// Handler forwards the request. The client address is resolved here, using
// the gateway's trusted-proxy settings, and asserted to the service.
func (p *Proxy) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Header.Set(httpx.HeaderClientIP, c.ClientIP())
		p.rp.ServeHTTP(c.Writer, c.Request)
	}
}
