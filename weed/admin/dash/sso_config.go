package dash

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/seaweedfs/seaweedfs/weed/util"
)

// SSOConfig holds OIDC single sign-on settings for the admin UI.
// When Enabled is true, SSO replaces local username/password login.
type SSOConfig struct {
	Enabled      bool
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

const (
	defaultSSOScopes = "openid,profile,email"

	// Session keys for the in-flight OIDC authorization code flow.
	SSOStateSessionKey    = "sso_state"
	SSONonceSessionKey    = "sso_nonce"
	SSOVerifierSessionKey = "sso_verifier"
)

// LoadSSOConfig reads the [admin.sso] section from viper (security.toml or
// WEED_ADMIN_SSO_* environment variables). It never returns nil.
func LoadSSOConfig() *SSOConfig {
	vp := util.GetViper()
	cfg := &SSOConfig{
		Enabled:      vp.GetBool("admin.sso.enabled"),
		Issuer:       strings.TrimRight(strings.TrimSpace(vp.GetString("admin.sso.issuer")), "/"),
		ClientID:     strings.TrimSpace(vp.GetString("admin.sso.client-id")),
		ClientSecret: vp.GetString("admin.sso.client-secret"),
		RedirectURL:  strings.TrimSpace(vp.GetString("admin.sso.redirect-url")),
	}
	scopes := strings.TrimSpace(vp.GetString("admin.sso.scopes"))
	if scopes == "" {
		scopes = defaultSSOScopes
	}
	for _, scope := range strings.Split(scopes, ",") {
		if scope = strings.TrimSpace(scope); scope != "" {
			cfg.Scopes = append(cfg.Scopes, scope)
		}
	}
	return cfg
}

// Validate reports whether the SSO settings are complete enough to start the
// OIDC authorization code flow.
func (c *SSOConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	issuer, err := url.Parse(c.Issuer)
	if err != nil || issuer.Scheme != "https" && issuer.Scheme != "http" || issuer.Host == "" {
		return fmt.Errorf("admin.sso.issuer must be an absolute http(s) URL, got %q", c.Issuer)
	}
	if c.ClientID == "" {
		return fmt.Errorf("admin.sso.client-id is required when SSO is enabled")
	}
	redirect, err := url.Parse(c.RedirectURL)
	if err != nil || redirect.Scheme != "https" && redirect.Scheme != "http" || redirect.Host == "" {
		return fmt.Errorf("admin.sso.redirect-url must be an absolute http(s) URL registered with the provider, got %q", c.RedirectURL)
	}
	if len(c.Scopes) == 0 {
		return fmt.Errorf("admin.sso.scopes must include at least the openid scope")
	}
	return nil
}

// GenerateSSOState returns a random OIDC state parameter, used both as CSRF
// protection for the callback and to bind the callback to this browser.
func GenerateSSOState() (string, error) {
	return randomToken(32)
}

// GeneratePKCEVerifier returns a random PKCE code_verifier (RFC 7636).
func GeneratePKCEVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// PKCES256Challenge derives the S256 code_challenge from a code_verifier.
func PKCES256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ConstantTimeEqual compares two strings without leaking length or content
// through timing.
func ConstantTimeEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func randomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
