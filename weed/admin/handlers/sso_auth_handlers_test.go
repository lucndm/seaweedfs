package handlers

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/sessions"

	"github.com/seaweedfs/seaweedfs/weed/admin/dash"
)

func newSSOTestHandlers(t *testing.T, ssoConfig *dash.SSOConfig) *AuthHandlers {
	t.Helper()
	authKey := make([]byte, 32)
	encKey := make([]byte, 32)
	if _, err := rand.Read(authKey); err != nil {
		t.Fatalf("rand auth key: %v", err)
	}
	if _, err := rand.Read(encKey); err != nil {
		t.Fatalf("rand enc key: %v", err)
	}
	store := sessions.NewCookieStore(authKey, encKey)
	return NewAuthHandlers(nil, store, ssoConfig)
}

func TestHandleSSOLogin_Disabled(t *testing.T) {
	h := newSSOTestHandlers(t, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/login", nil)
	h.HandleSSOLogin(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=SSO+is+not+enabled") {
		t.Errorf("Location = %q, want login redirect with error", loc)
	}
}

func TestHandleSSOCallback_Disabled(t *testing.T) {
	h := newSSOTestHandlers(t, &dash.SSOConfig{Enabled: false})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/callback?code=x&state=y", nil)
	h.HandleSSOCallback(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
}

func TestHandleSSOCallback_ProviderError(t *testing.T) {
	h := newSSOTestHandlers(t, enabledSSOConfig())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/callback?error=access_denied&error_description=user+denied", nil)
	h.HandleSSOCallback(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "user+denied") {
		t.Errorf("Location = %q, want provider error description", loc)
	}
}

func TestHandleSSOCallback_StateMismatch(t *testing.T) {
	h := newSSOTestHandlers(t, enabledSSOConfig())

	// Seed a session with SSO flow state, then present a different state.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/login", nil)
	h.HandleSSOLogin(rec, req)
	// HandleSSOLogin fails on provider discovery (no provider in tests);
	// seed the session directly instead.
	seedReq := httptest.NewRequest(http.MethodGet, "/", nil)
	seedRec := httptest.NewRecorder()
	session, err := h.sessionStore.New(seedReq, dash.SessionName())
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	session.Values[dash.SSOStateSessionKey] = "expected-state"
	session.Values[dash.SSONonceSessionKey] = "expected-nonce"
	session.Values[dash.SSOVerifierSessionKey] = "expected-verifier"
	if err := session.Save(seedReq, seedRec); err != nil {
		t.Fatalf("save session: %v", err)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/auth/sso/callback?code=abc&state=evil-state", nil)
	req.Header.Set("Cookie", cookieFrom(seedRec))
	h.HandleSSOCallback(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "Invalid+SSO+state") {
		t.Errorf("Location = %q, want invalid state error", loc)
	}
}

func TestHandleSSOCallback_MissingSessionState(t *testing.T) {
	h := newSSOTestHandlers(t, enabledSSOConfig())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/callback?code=abc&state=whatever", nil)
	h.HandleSSOCallback(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "expired") {
		t.Errorf("Location = %q, want expired session error", loc)
	}
}

func enabledSSOConfig() *dash.SSOConfig {
	return &dash.SSOConfig{
		Enabled:     true,
		Issuer:      "https://auth.example.com",
		ClientID:    "client-id",
		RedirectURL: "https://admin.example.com/auth/sso/callback",
		Scopes:      []string{"openid"},
	}
}

func cookieFrom(rec *httptest.ResponseRecorder) string {
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		return ""
	}
	value := cookies[0].Name + "=" + cookies[0].Value
	for _, c := range cookies[1:] {
		value += "; " + c.Name + "=" + c.Value
	}
	return value
}
