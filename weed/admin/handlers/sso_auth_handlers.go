package handlers

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/seaweedfs/seaweedfs/weed/admin/dash"
	"github.com/seaweedfs/seaweedfs/weed/glog"
)

const ssoDiscoveryTimeout = 10 * time.Second

// ssoFlow lazily performs OIDC discovery on first use so that an unreachable
// provider never blocks admin startup; it surfaces as a login-page error.
type ssoFlow struct {
	once     sync.Once
	provider *oidc.Provider
	err      error
}

func (a *AuthHandlers) ssoEnabled() bool {
	return a.ssoConfig != nil && a.ssoConfig.Enabled
}

func (a *AuthHandlers) ssoProvider() (*oidc.Provider, error) {
	if a.sso == nil {
		a.sso = &ssoFlow{}
	}
	a.sso.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), ssoDiscoveryTimeout)
		defer cancel()
		a.sso.provider, a.sso.err = oidc.NewProvider(ctx, a.ssoConfig.Issuer)
		if a.sso.err != nil {
			glog.Errorf("SSO OIDC discovery for issuer %s failed: %v", a.ssoConfig.Issuer, a.sso.err)
		}
	})
	return a.sso.provider, a.sso.err
}

func (a *AuthHandlers) ssoOAuth2Config(provider *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     a.ssoConfig.ClientID,
		ClientSecret: a.ssoConfig.ClientSecret,
		RedirectURL:  a.ssoConfig.RedirectURL,
		Scopes:       a.ssoConfig.Scopes,
		Endpoint:     provider.Endpoint(),
	}
}

// HandleSSOLogin starts the OIDC authorization code flow: it stores state,
// nonce and PKCE verifier in the session, then redirects to the provider.
func (a *AuthHandlers) HandleSSOLogin(w http.ResponseWriter, r *http.Request) {
	prefix := dash.URLPrefixFromContext(r.Context())
	if !a.ssoEnabled() {
		http.Redirect(w, r, ssoErrorRedirect(prefix, "SSO is not enabled"), http.StatusSeeOther)
		return
	}
	provider, err := a.ssoProvider()
	if err != nil {
		http.Redirect(w, r, ssoErrorRedirect(prefix, "SSO provider is unreachable. Please try again later."), http.StatusSeeOther)
		return
	}

	state, err := dash.GenerateSSOState()
	if err != nil {
		http.Redirect(w, r, ssoErrorRedirect(prefix, "Unable to start SSO login. Please try again."), http.StatusSeeOther)
		return
	}
	nonce, err := dash.GenerateSSOState()
	if err != nil {
		http.Redirect(w, r, ssoErrorRedirect(prefix, "Unable to start SSO login. Please try again."), http.StatusSeeOther)
		return
	}
	verifier, err := dash.GeneratePKCEVerifier()
	if err != nil {
		http.Redirect(w, r, ssoErrorRedirect(prefix, "Unable to start SSO login. Please try again."), http.StatusSeeOther)
		return
	}

	session, err := a.sessionStore.Get(r, dash.SessionName())
	if err != nil {
		http.Redirect(w, r, ssoErrorRedirect(prefix, "Unable to create session. Please try again or contact administrator."), http.StatusSeeOther)
		return
	}
	for key := range session.Values {
		delete(session.Values, key)
	}
	session.Values[dash.SSOStateSessionKey] = state
	session.Values[dash.SSONonceSessionKey] = nonce
	session.Values[dash.SSOVerifierSessionKey] = verifier
	if err := session.Save(r, w); err != nil {
		glog.Errorf("Failed to save session during SSO login: %v", err)
		http.Redirect(w, r, ssoErrorRedirect(prefix, "Unable to create session. Please try again or contact administrator."), http.StatusSeeOther)
		return
	}

	authURL := a.ssoOAuth2Config(provider).AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", dash.PKCES256Challenge(verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// HandleSSOCallback completes the OIDC authorization code flow: it validates
// state and PKCE, verifies the ID token, and creates an authenticated session.
func (a *AuthHandlers) HandleSSOCallback(w http.ResponseWriter, r *http.Request) {
	prefix := dash.URLPrefixFromContext(r.Context())
	if !a.ssoEnabled() {
		http.Redirect(w, r, ssoErrorRedirect(prefix, "SSO is not enabled"), http.StatusSeeOther)
		return
	}
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		detail := errParam
		if desc := r.URL.Query().Get("error_description"); desc != "" {
			detail = desc
		}
		glog.Warningf("SSO callback returned an error from the provider: %s", detail)
		http.Redirect(w, r, ssoErrorRedirect(prefix, "SSO login was rejected: "+detail), http.StatusSeeOther)
		return
	}

	session, err := a.sessionStore.Get(r, dash.SessionName())
	if err != nil {
		http.Redirect(w, r, ssoErrorRedirect(prefix, "Unable to create session. Please try again or contact administrator."), http.StatusSeeOther)
		return
	}
	expectedState, _ := session.Values[dash.SSOStateSessionKey].(string)
	expectedNonce, _ := session.Values[dash.SSONonceSessionKey].(string)
	verifier, _ := session.Values[dash.SSOVerifierSessionKey].(string)
	if expectedState == "" || expectedNonce == "" || verifier == "" {
		http.Redirect(w, r, ssoErrorRedirect(prefix, "SSO login session expired. Please try again."), http.StatusSeeOther)
		return
	}
	if !dash.ConstantTimeEqual(expectedState, r.URL.Query().Get("state")) {
		http.Redirect(w, r, ssoErrorRedirect(prefix, "Invalid SSO state"), http.StatusSeeOther)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Redirect(w, r, ssoErrorRedirect(prefix, "Missing SSO authorization code"), http.StatusSeeOther)
		return
	}

	provider, err := a.ssoProvider()
	if err != nil {
		http.Redirect(w, r, ssoErrorRedirect(prefix, "SSO provider is unreachable. Please try again later."), http.StatusSeeOther)
		return
	}
	oauthConfig := a.ssoOAuth2Config(provider)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	token, err := oauthConfig.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		glog.Warningf("SSO code exchange failed: %v", err)
		http.Redirect(w, r, ssoErrorRedirect(prefix, "SSO login failed: unable to exchange authorization code"), http.StatusSeeOther)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Redirect(w, r, ssoErrorRedirect(prefix, "SSO login failed: provider did not return an ID token"), http.StatusSeeOther)
		return
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: oauthConfig.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		glog.Warningf("SSO ID token verification failed: %v", err)
		http.Redirect(w, r, ssoErrorRedirect(prefix, "SSO login failed: invalid ID token"), http.StatusSeeOther)
		return
	}
	if !dash.ConstantTimeEqual(expectedNonce, idToken.Nonce) {
		http.Redirect(w, r, ssoErrorRedirect(prefix, "SSO login failed: nonce mismatch"), http.StatusSeeOther)
		return
	}

	var claims struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Redirect(w, r, ssoErrorRedirect(prefix, "SSO login failed: unable to read ID token claims"), http.StatusSeeOther)
		return
	}
	username := claims.Email
	if username == "" {
		username = claims.PreferredUsername
	}
	if username == "" {
		username = claims.Name
	}
	if username == "" {
		username = idToken.Subject
	}

	// SSO users receive the admin role; local read-only accounts stay separate.
	if err := dash.CreateAuthenticatedSession(session, r, w, username, "admin"); err != nil {
		glog.Errorf("Failed to save session for SSO user %s: %v", username, err)
		http.Redirect(w, r, ssoErrorRedirect(prefix, "Unable to create session. Please try again or contact administrator."), http.StatusSeeOther)
		return
	}

	glog.V(1).Infof("SSO login succeeded for user %s (subject %s)", username, idToken.Subject)
	http.Redirect(w, r, prefix+"/admin", http.StatusSeeOther)
}

func ssoErrorRedirect(prefix, message string) string {
	values := url.Values{}
	values.Set("error", strings.TrimSpace(message))
	return prefix + "/login?" + values.Encode()
}
