package sso

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type HMACDeviceSecretProvider struct {
	secret []byte
}

func NewHMACDeviceSecretProvider(secret string) *HMACDeviceSecretProvider {
	return &HMACDeviceSecretProvider{secret: []byte(secret)}
}

func (p *HMACDeviceSecretProvider) GenerateDeviceSecret(input GenerateDeviceSecretInput) (string, error) {
	c := DeviceSecretClaims{
		Issuer:   input.Issuer,
		Expiry:   input.Expiry.Unix(),
		ClientID: input.ClientID,
		Scope:    input.Scope,
		ACR:      input.ACR,
		AuthID:   input.AuthID,
		Claims:   input.Claims,
	}
	c.CNF.JKT = input.CNFJKT
	return signHS256(c, p.secret)
}

func (p *HMACDeviceSecretProvider) ValidateDeviceSecret(deviceSecret string) (*DeviceSecretClaims, error) {
	var c DeviceSecretClaims
	if err := verifyHS256(deviceSecret, p.secret, &c); err != nil {
		return nil, err
	}
	if c.Expiry <= time.Now().Unix() {
		return nil, errors.New("device secret expired")
	}
	if c.ClientID == "" || c.AuthID == "" || c.CNF.JKT == "" {
		return nil, errors.New("device secret missing mandatory claims")
	}
	return &c, nil
}

func signHS256(claims any, secret []byte) (string, error) {
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(h)
	encodedPayload := base64.RawURLEncoding.EncodeToString(p)
	msg := encodedHeader + "." + encodedPayload
	sig := computeHMAC([]byte(msg), secret)
	return msg + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func verifyHS256(token string, secret []byte, out any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid jwt format")
	}
	msg := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	expected := computeHMAC([]byte(msg), secret)
	if !hmac.Equal(sig, expected) {
		return errors.New("invalid jwt signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	if err = json.Unmarshal(payload, out); err != nil {
		return err
	}
	return nil
}

func computeHMAC(msg []byte, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(msg)
	return h.Sum(nil)
}

func DSHash(deviceSecret string) string {
	sum := sha256.Sum256([]byte(deviceSecret))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func SignJWT(claims map[string]any, secret []byte) (string, error) {
	return signHS256(claims, secret)
}

func VerifyJWT(token string, secret []byte, out any) error {
	return verifyHS256(token, secret, out)
}
