package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ShubhamK-07/MOsip2/internal/sso"
)

const deviceSSOScope = "device_sso"

type Config struct {
	Issuer                        string
	SigningSecret                 string
	RequireReconsentOnScopeChange bool
}

type Client struct {
	ID                         string
	AllowedAuthorizationScopes map[string]struct{}
}

type Session struct {
	SID        string
	ClientID   string
	Scope      map[string]struct{}
	CNFJKT     string
	DeviceSSO  bool
	CreatedAt  time.Time
	RawScope   string
	UserClaims map[string]any
}

type Server struct {
	cfg            Config
	deviceProvider sso.DeviceSecretProvider
	clients        map[string]Client
	sessions       map[string]Session
	mu             sync.RWMutex
}

func New(cfg Config) http.Handler {
	return NewServer(cfg)
}

func NewServer(cfg Config) *ServerWithMux {
	s := &Server{
		cfg:            cfg,
		deviceProvider: sso.NewHMACDeviceSecretProvider(cfg.SigningSecret),
		clients: map[string]Client{
			"super-app": {
				ID:                         "super-app",
				AllowedAuthorizationScopes: toSet([]string{"openid", "profile", "email", "device_sso"}),
			},
			"child-app": {
				ID:                         "child-app",
				AllowedAuthorizationScopes: toSet([]string{"openid", "profile", "email", "device_sso"}),
			},
		},
		sessions: map[string]Session{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", s.handleToken)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return &ServerWithMux{Server: s, mux: mux}
}

type ServerWithMux struct {
	*Server
	mux *http.ServeMux
}

func (s *ServerWithMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		s.handleAuthorizationCode(w, r)
	case "token_exchange", "urn:ietf:params:oauth:grant-type:token-exchange":
		s.handleTokenExchange(w, r)
	default:
		writeError(w, http.StatusBadRequest, "unsupported_grant_type", "grant type is not supported")
	}
}

func (s *Server) handleAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	client, ok := s.clients[r.Form.Get("client_id")]
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	}
	scopes := strings.Fields(r.Form.Get("scope"))
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	for _, sc := range scopes {
		if _, allowed := client.AllowedAuthorizationScopes[sc]; !allowed {
			writeError(w, http.StatusBadRequest, "invalid_scope", "scope not allowed for client")
			return
		}
	}

	hasDeviceSSO := containsScope(scopes, deviceSSOScope)
	if hasDeviceSSO {
		if _, allowed := client.AllowedAuthorizationScopes[deviceSSOScope]; !allowed {
			writeError(w, http.StatusBadRequest, "invalid_scope", "device_sso not allowed for client")
			return
		}
	}

	sid := r.Form.Get("sid")
	if sid == "" {
		sid = randomToken(20)
	}
	cnfJKT := r.Form.Get("cnf_jkt")
	if cnfJKT == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "cnf_jkt is required")
		return
	}
	claims := map[string]any{}
	if rawClaims := r.Form.Get("claims"); rawClaims != "" {
		_ = json.Unmarshal([]byte(rawClaims), &claims)
	}

	accessToken := randomToken(32)
	rawScope := normalizeScope(scopes)

	idClaims := map[string]any{
		"iss":   s.cfg.Issuer,
		"sub":   "user-123",
		"aud":   client.ID,
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
		"sid":   sid,
		"scope": rawScope,
	}

	resp := map[string]any{
		"access_token": accessToken,
		"token_type":   "DPoP",
		"expires_in":   600,
		"scope":        rawScope,
	}

	if hasDeviceSSO {
		deviceSecret, err := s.deviceProvider.GenerateDeviceSecret(sso.GenerateDeviceSecretInput{
			ClientID: client.ID,
			Scope:    rawScope,
			ACR:      r.Form.Get("acr"),
			AuthID:   r.Form.Get("auth_id"),
			Claims:   claims,
			CNFJKT:   cnfJKT,
			Expiry:   time.Now().Add(10 * time.Minute),
			Issuer:   s.cfg.Issuer,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", "failed to issue device secret")
			return
		}
		idClaims["ds_hash"] = sso.DSHash(deviceSecret)
		idClaims["device_secret"] = deviceSecret
		resp["device_secret"] = deviceSecret
	}

	idToken, err := signMap(idClaims, []byte(s.cfg.SigningSecret))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to issue id token")
		return
	}
	resp["id_token"] = idToken

	s.mu.Lock()
	s.sessions[sid] = Session{
		SID:        sid,
		ClientID:   client.ID,
		Scope:      toSet(scopes),
		CNFJKT:     cnfJKT,
		DeviceSSO:  hasDeviceSSO,
		CreatedAt:  time.Now(),
		RawScope:   rawScope,
		UserClaims: claims,
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	scopes := strings.Fields(r.Form.Get("scope"))
	if containsScope(scopes, deviceSSOScope) {
		writeError(w, http.StatusBadRequest, "invalid_scope", "device_sso is not allowed in token_exchange")
		return
	}

	actorType := r.Form.Get("actor_token_type")
	if actorType != sso.DeviceSecretTokenType {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid actor_token_type")
		return
	}
	deviceSecret := r.Form.Get("actor_token")
	idToken := r.Form.Get("subject_token")
	if deviceSecret == "" || idToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "actor_token and subject_token are required")
		return
	}

	dsClaims, err := s.deviceProvider.ValidateDeviceSecret(deviceSecret)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_grant", "invalid device secret")
		return
	}

	idClaims := map[string]any{}
	if err = verifyMap(idToken, []byte(s.cfg.SigningSecret), &idClaims); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_grant", "invalid id_token")
		return
	}

	if idClaims["ds_hash"] != sso.DSHash(deviceSecret) {
		writeError(w, http.StatusUnauthorized, "invalid_grant", "device secret is not bound to id_token")
		return
	}
	sid, _ := idClaims["sid"].(string)
	if sid == "" {
		writeError(w, http.StatusUnauthorized, "invalid_grant", "id_token missing sid")
		return
	}

	s.mu.RLock()
	session, ok := s.sessions[sid]
	s.mu.RUnlock()
	if !ok || !session.DeviceSSO {
		writeError(w, http.StatusUnauthorized, "invalid_grant", "invalid or expired session")
		return
	}

	if _, ok = session.Scope[deviceSSOScope]; !ok {
		writeError(w, http.StatusUnauthorized, "invalid_grant", "source session is not device_sso-enabled")
		return
	}

	dpopJKT := r.Header.Get("DPoP-JKT")
	if dpopJKT == "" || dpopJKT != dsClaims.CNF.JKT {
		writeError(w, http.StatusUnauthorized, "invalid_dpop_proof", "cnf.jkt and DPoP key thumbprint mismatch")
		return
	}

	if len(scopes) == 0 {
		scopes = strings.Fields(session.RawScope)
	}
	for _, sc := range scopes {
		if _, ok = session.Scope[sc]; !ok {
			writeError(w, http.StatusBadRequest, "invalid_scope", "requested scope must be a subset of source scope")
			return
		}
	}

	clientID := r.Form.Get("client_id")
	if clientID == "" {
		clientID = "child-app"
	}
	client, exists := s.clients[clientID]
	if !exists {
		writeError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	}
	if _, allowed := client.AllowedAuthorizationScopes[deviceSSOScope]; !allowed {
		writeError(w, http.StatusBadRequest, "invalid_scope", "client is not eligible for native sso")
		return
	}
	for _, sc := range scopes {
		if _, allowed := client.AllowedAuthorizationScopes[sc]; !allowed {
			writeError(w, http.StatusBadRequest, "invalid_scope", "scope not allowed for client")
			return
		}
	}
	requestedScope := normalizeScope(scopes)
	if s.cfg.RequireReconsentOnScopeChange && requestedScope != session.RawScope {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":             "interaction_required",
			"error_description": "scope change requires re-consent",
			"required_action":   "reconsent",
			"original_scope":    session.RawScope,
			"requested_scope":   requestedScope,
		})
		return
	}

	resp := map[string]any{
		"access_token": randomToken(32),
		"token_type":   "DPoP",
		"expires_in":   600,
		"scope":        requestedScope,
	}
	newIDClaims := map[string]any{
		"iss":   s.cfg.Issuer,
		"sub":   "user-123",
		"aud":   client.ID,
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
		"sid":   sid,
		"scope": requestedScope,
	}
	newIDToken, err := signMap(newIDClaims, []byte(s.cfg.SigningSecret))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to issue id token")
		return
	}
	resp["id_token"] = newIDToken
	writeJSON(w, http.StatusOK, resp)
}

func normalizeScope(scopes []string) string {
	sorted := append([]string(nil), scopes...)
	sort.Strings(sorted)
	return strings.Join(sorted, " ")
}

func containsScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

func toSet(scopes []string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, scope := range scopes {
		m[scope] = struct{}{}
	}
	return m
}

func randomToken(size int) string {
	buf := make([]byte, size)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

func writeError(w http.ResponseWriter, status int, code string, description string) {
	writeJSON(w, status, map[string]any{"error": code, "error_description": description})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func signMap(claims map[string]any, secret []byte) (string, error) {
	return sso.SignJWT(claims, secret)
}

func verifyMap(token string, secret []byte, out *map[string]any) error {
	return sso.VerifyJWT(token, secret, out)
}
