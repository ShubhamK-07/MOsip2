package sso

import "time"

const DeviceSecretTokenType = "urn:openid:params:token-type:device-secret"

type DeviceSecretClaims struct {
	Issuer   string         `json:"iss"`
	Expiry   int64          `json:"exp"`
	ClientID string         `json:"client_id"`
	Scope    string         `json:"scope"`
	ACR      string         `json:"acr,omitempty"`
	AuthID   string         `json:"auth_id"`
	Claims   map[string]any `json:"claims,omitempty"`
	CNF      struct {
		JKT string `json:"jkt"`
	} `json:"cnf"`
}

type DeviceSecretProvider interface {
	GenerateDeviceSecret(input GenerateDeviceSecretInput) (string, error)
	ValidateDeviceSecret(deviceSecret string) (*DeviceSecretClaims, error)
}

type GenerateDeviceSecretInput struct {
	ClientID string
	Scope    string
	ACR      string
	AuthID   string
	Claims   map[string]any
	CNFJKT   string
	Expiry   time.Time
	Issuer   string
}
