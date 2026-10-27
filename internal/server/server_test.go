package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthorizationCodeReturnsDeviceSecretWhenRequested(t *testing.T) {
	h := New(Config{Issuer: "https://issuer", SigningSecret: "test-secret"})
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "super-app")
	form.Set("scope", "openid profile device_sso")
	form.Set("auth_id", "auth-1")
	form.Set("cnf_jkt", "jkt-1")
	form.Set("sid", "sid-1")
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := httptest.NewRecorder()

	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["device_secret"]; !ok {
		t.Fatalf("expected device_secret in response")
	}
	if _, ok := body["id_token"]; !ok {
		t.Fatalf("expected id_token in response")
	}
}

func TestTokenExchangeRejectsDeviceSSOScope(t *testing.T) {
	h := New(Config{Issuer: "https://issuer", SigningSecret: "test-secret"})

	form := url.Values{}
	form.Set("grant_type", "token_exchange")
	form.Set("actor_token_type", "urn:openid:params:token-type:device-secret")
	form.Set("actor_token", "x")
	form.Set("subject_token", "y")
	form.Set("scope", "openid device_sso")
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("expected 400, got %d: %s", res.Code, string(b))
	}
}

func TestTokenExchangeScopeSubsetAndDPoPValidation(t *testing.T) {
	h := New(Config{Issuer: "https://issuer", SigningSecret: "test-secret"})

	first := url.Values{}
	first.Set("grant_type", "authorization_code")
	first.Set("client_id", "super-app")
	first.Set("scope", "openid profile email device_sso")
	first.Set("auth_id", "auth-1")
	first.Set("cnf_jkt", "jkt-1")
	first.Set("sid", "sid-1")
	firstReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(first.Encode()))
	firstReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	firstRes := httptest.NewRecorder()
	h.ServeHTTP(firstRes, firstReq)
	if firstRes.Code != http.StatusOK {
		t.Fatalf("first login expected 200, got %d: %s", firstRes.Code, firstRes.Body.String())
	}
	var firstBody map[string]any
	_ = json.NewDecoder(firstRes.Body).Decode(&firstBody)
	deviceSecret := firstBody["device_secret"].(string)
	idToken := firstBody["id_token"].(string)

	// request scope not subset -> fail
	bad := url.Values{}
	bad.Set("grant_type", "token_exchange")
	bad.Set("client_id", "child-app")
	bad.Set("actor_token_type", "urn:openid:params:token-type:device-secret")
	bad.Set("actor_token", deviceSecret)
	bad.Set("subject_token", idToken)
	bad.Set("scope", "openid admin")
	badReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(bad.Encode()))
	badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badReq.Header.Set("DPoP-JKT", "jkt-1")
	badRes := httptest.NewRecorder()
	h.ServeHTTP(badRes, badReq)
	if badRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-subset scope, got %d: %s", badRes.Code, badRes.Body.String())
	}

	// valid subset and DPoP match -> success
	good := url.Values{}
	good.Set("grant_type", "token_exchange")
	good.Set("client_id", "child-app")
	good.Set("actor_token_type", "urn:openid:params:token-type:device-secret")
	good.Set("actor_token", deviceSecret)
	good.Set("subject_token", idToken)
	good.Set("scope", "openid profile")
	goodReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(good.Encode()))
	goodReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	goodReq.Header.Set("DPoP-JKT", "jkt-1")
	goodRes := httptest.NewRecorder()
	h.ServeHTTP(goodRes, goodReq)
	if goodRes.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", goodRes.Code, goodRes.Body.String())
	}
}
