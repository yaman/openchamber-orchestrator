package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Validator checks the browser session against oauth2-proxy and extracts the
// authenticated principal (email). The orchestrator itself never does OIDC;
// it delegates to oauth2-proxy like Caddy's forward_auth would.
type Validator struct {
	proxyURL      string
	allowedDomain string
	client        *http.Client
	logger        *slog.Logger
}

func NewValidator(proxyURL, allowedDomain string, logger *slog.Logger) *Validator {
	return &Validator{
		proxyURL:      strings.TrimRight(proxyURL, "/"),
		allowedDomain: strings.ToLower(allowedDomain),
		client:        &http.Client{Timeout: 5 * time.Second},
		logger:        logger,
	}
}

// Principal is the authenticated identity, or empty if unauthenticated.
type Principal struct {
	Email string
	// RefreshCookies carries Set-Cookie headers from oauth2-proxy (session
	// refresh on 202) that must be forwarded to the browser.
	RefreshCookies []string
}

// Validate forwards the incoming request to oauth2-proxy's /oauth2/auth
// endpoint. 200 and 202 both mean the session is valid (202 = oauth2-proxy
// refreshed the session cookie and set a new one); oauth2-proxy also sets
// X-Auth-Request-Email / X-Auth-Request-User response headers that carry
// the authenticated identity.
func (v *Validator) Validate(ctx context.Context, req *http.Request) (Principal, error) {
	target := v.proxyURL + "/oauth2/auth"

	outReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Principal{}, fmt.Errorf("build auth request: %w", err)
	}
	for _, k := range []string{
		"Cookie", "X-Forwarded-Host", "X-Forwarded-Proto",
		"X-Forwarded-Uri", "X-Forwarded-For", "X-Real-IP",
	} {
		if v := req.Header.Get(k); v != "" {
			outReq.Header.Set(k, v)
		}
	}
	if u := req.Header.Get("X-Forwarded-Uri"); u == "" {
		outReq.Header.Set("X-Forwarded-Uri", req.URL.RequestURI())
	}

	resp, err := v.client.Do(outReq)
	if err != nil {
		return Principal{}, fmt.Errorf("oauth2-proxy unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return Principal{}, nil
	}
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted {
		email := strings.ToLower(strings.TrimSpace(resp.Header.Get("X-Auth-Request-Email")))
		if email == "" {
			email = strings.ToLower(strings.TrimSpace(resp.Header.Get("X-Auth-Request-User")))
		}
		if email != "" && !strings.Contains(email, "@") {
			v.logger.Warn("auth: header without @", "header", email)
			return Principal{}, nil
		}
		if v.allowedDomain != "" && !strings.HasSuffix(email, "@"+v.allowedDomain) {
			v.logger.Warn("auth: email outside allowed domain", "email", email)
			return Principal{}, nil
		}
		return Principal{
			Email:          email,
			RefreshCookies: resp.Header.Values("Set-Cookie"),
		}, nil
	}

	return Principal{}, fmt.Errorf("oauth2-proxy unexpected status %d", resp.StatusCode)
}
