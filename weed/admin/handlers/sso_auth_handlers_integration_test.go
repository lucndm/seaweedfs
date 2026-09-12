package handlers

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/seaweedfs/seaweedfs/weed/admin/dash"
)

// mockOIDCProvider stands in for a Zitadel instance: it serves discovery,
// JWKS and a token endpoint, and asserts the PKCE code_verifier presented
// during the code exchange matches the S256 challenge of the seeded session.
type mockOIDCProvider struct {
	server       *httptest.Server
	privateKey   *rsa.PrivateKey
	publicJWK    map[string]interface{}
	seenVerifier string
}

func newMockOIDCProvider(t *testing.T) *mockOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	m := &mockOIDCProvider{privateKey: key}
	pub := key.Public().(*rsa.PublicKey)
	m.publicJWK = map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": "test-key",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                m.server.URL,
			"authorization_endpoint":                m.server.URL + "/authorize",
			"token_endpoint":                        m.server.URL + "/token",
			"jwks_uri":                              m.server.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{m.publicJWK}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		m.seenVerifier = r.FormValue("code_verifier")
		idToken, err := m.signIDToken("sso-user@example.com", "user-42", "test-nonce")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "at",
			"token_type":   "Bearer",
			"id_token":     idToken,
			"expires_in":   3600,
		})
	})
	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

// signIDToken returns an RS256 JWT with the claims go-oidc validates.
func (m *mockOIDCProvider) signIDToken(email, sub, nonce string) (string, error) {
	now := time.Now()
	header, err := json.Marshal(map[string]interface{}{"alg": "RS256", "typ": "JWT", "kid": "test-key"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]interface{}{
		"iss":                m.server.URL,
		"aud":                "test-client",
		"sub":                sub,
		"email":              email,
		"preferred_username": email,
		"nonce":              nonce,
		"iat":                now.Unix(),
		"exp":                now.Add(time.Hour).Unix(),
	})
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, m.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func TestHandleSSOCallback_HappyPath(t *testing.T) {
	mock := newMockOIDCProvider(t)
	cfg := &dash.SSOConfig{
		Enabled:     true,
		Issuer:      mock.server.URL,
		ClientID:    "test-client",
		RedirectURL: "http://admin.test/auth/sso/callback",
		Scopes:      []string{"openid"},
	}
	h := newSSOTestHandlers(t, cfg)

	verifier, err := dash.GeneratePKCEVerifier()
	if err != nil {
		t.Fatalf("GeneratePKCEVerifier: %v", err)
	}
	state := "integration-state"
	nonce := "test-nonce"
	seedReq := httptest.NewRequest(http.MethodGet, "/", nil)
	seedRec := httptest.NewRecorder()
	session, err := h.sessionStore.New(seedReq, dash.SessionName())
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	session.Values[dash.SSOStateSessionKey] = state
	session.Values[dash.SSONonceSessionKey] = nonce
	session.Values[dash.SSOVerifierSessionKey] = verifier
	if err := session.Save(seedReq, seedRec); err != nil {
		t.Fatalf("save session: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/callback?code=the-code&state="+state, nil)
	req.Header.Set("Cookie", cookieFrom(seedRec))
	h.HandleSSOCallback(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusSeeOther, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.HasSuffix(loc, "/admin") {
		t.Errorf("Location = %q, want redirect to /admin", loc)
	}

	// The mock provider must have received the PKCE verifier matching the
	// S256 challenge derived from the session-stored code_verifier.
	if mock.seenVerifier != verifier {
		t.Errorf("token endpoint received verifier %q, want %q", mock.seenVerifier, verifier)
	}

	// The resulting session must be authenticated as an admin.
	resultCookies := rec.Result().Cookies()
	finalReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	for _, c := range resultCookies {
		finalReq.AddCookie(c)
	}
	finalSession, err := h.sessionStore.Get(finalReq, dash.SessionName())
	if err != nil {
		t.Fatalf("load final session: %v", err)
	}
	if authenticated, _ := finalSession.Values["authenticated"].(bool); !authenticated {
		t.Error("session not authenticated")
	}
	if role, _ := finalSession.Values["role"].(string); role != "admin" {
		t.Errorf("role = %q, want admin", role)
	}
	if username, _ := finalSession.Values["username"].(string); username != "sso-user@example.com" {
		t.Errorf("username = %q, want sso-user@example.com", username)
	}
	if _, ok := finalSession.Values[dash.SSOStateSessionKey]; ok {
		t.Error("SSO flow state must be cleared from the session after login")
	}
}
