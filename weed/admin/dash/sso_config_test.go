package dash

import (
	"testing"
)

func TestLoadSSOConfig_DisabledByDefault(t *testing.T) {
	cfg := LoadSSOConfig()
	if cfg == nil {
		t.Fatal("LoadSSOConfig must never return nil")
	}
	if cfg.Enabled {
		t.Error("SSO must be disabled by default")
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("disabled config must validate: %v", err)
	}
}

// TestLoadSSOConfig_FromEnv pins the WEED_ADMIN_SSO_* environment contract:
// hyphenated config keys (client-id, redirect-url) must resolve env vars with
// underscores (WEED_ADMIN_SSO_CLIENT_ID). Regression guard for the viper
// EnvKeyReplacer missing the "-" to "_" mapping.
func TestLoadSSOConfig_FromEnv(t *testing.T) {
	t.Setenv("WEED_ADMIN_SSO_ENABLED", "true")
	t.Setenv("WEED_ADMIN_SSO_ISSUER", "https://auth.example.com/")
	t.Setenv("WEED_ADMIN_SSO_CLIENT_ID", "env-client")
	t.Setenv("WEED_ADMIN_SSO_CLIENT_SECRET", "env-secret")
	t.Setenv("WEED_ADMIN_SSO_REDIRECT_URL", "https://admin.example.com/auth/sso/callback")

	cfg := LoadSSOConfig()
	if !cfg.Enabled {
		t.Fatal("enabled flag not read from env")
	}
	if cfg.ClientID != "env-client" {
		t.Errorf("ClientID = %q, want %q (env lookup for hyphenated key broken)", cfg.ClientID, "env-client")
	}
	if cfg.ClientSecret != "env-secret" {
		t.Errorf("ClientSecret = %q, want %q", cfg.ClientSecret, "env-secret")
	}
	if cfg.RedirectURL != "https://admin.example.com/auth/sso/callback" {
		t.Errorf("RedirectURL = %q, want the callback URL (trailing slash trimmed)", cfg.RedirectURL)
	}
	if cfg.Issuer != "https://auth.example.com" {
		t.Errorf("Issuer = %q, want trailing slash trimmed", cfg.Issuer)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("env-sourced config must validate: %v", err)
	}
}

func TestSSOConfigValidate(t *testing.T) {
	valid := &SSOConfig{
		Enabled:     true,
		Issuer:      "https://auth.example.com",
		ClientID:    "client",
		RedirectURL: "https://admin.example.com/auth/sso/callback",
		Scopes:      []string{"openid", "profile"},
	}
	if err := valid.Validate(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}

	tests := []struct {
		name string
		mut  func(*SSOConfig)
	}{
		{"empty issuer", func(c *SSOConfig) { c.Issuer = "" }},
		{"relative issuer", func(c *SSOConfig) { c.Issuer = "auth.example.com" }},
		{"empty client id", func(c *SSOConfig) { c.ClientID = "" }},
		{"relative redirect", func(c *SSOConfig) { c.RedirectURL = "/auth/sso/callback" }},
		{"empty scopes", func(c *SSOConfig) { c.Scopes = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := *valid
			tc.mut(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

// TestPKCES256Challenge checks the S256 test vector from RFC 7636 Appendix B.
func TestPKCES256Challenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := PKCES256Challenge(verifier); got != want {
		t.Errorf("PKCES256Challenge = %q, want %q", got, want)
	}
}

func TestGeneratePKCEVerifier(t *testing.T) {
	verifier, err := GeneratePKCEVerifier()
	if err != nil {
		t.Fatalf("GeneratePKCEVerifier: %v", err)
	}
	// RFC 7636: verifier length must be 43..128 ASCII characters.
	if len(verifier) < 43 || len(verifier) > 128 {
		t.Errorf("verifier length %d out of range", len(verifier))
	}
	other, err := GeneratePKCEVerifier()
	if err != nil {
		t.Fatalf("GeneratePKCEVerifier: %v", err)
	}
	if verifier == other {
		t.Error("verifier is not random")
	}
}

func TestGenerateSSOState(t *testing.T) {
	state, err := GenerateSSOState()
	if err != nil {
		t.Fatalf("GenerateSSOState: %v", err)
	}
	if len(state) != 64 { // 32 bytes hex-encoded
		t.Errorf("state length = %d, want 64", len(state))
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual("abc", "abc") {
		t.Error("equal strings must match")
	}
	if ConstantTimeEqual("abc", "abd") {
		t.Error("different strings must not match")
	}
	if ConstantTimeEqual("abc", "abcd") {
		t.Error("different lengths must not match")
	}
	if ConstantTimeEqual("", "") != true {
		t.Error("empty strings are equal")
	}
}
