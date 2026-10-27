# MOsip2

Minimal from-scratch Go implementation of Native SSO primitives for eSignet-style OIDC token handling.

## What is implemented

- `device_sso` scope handling for `authorization_code` token requests.
- Device Secret Provider interface with:
  - `GenerateDeviceSecret`
  - `ValidateDeviceSecret`
- Signed `device_secret` JWT including required claims:
  - `cnf.jkt`, `auth_id`, `exp`, `client_id`, `scope`, `acr`, `claims`, `iss`
- Token endpoint (`/oauth/token`) support for:
  - `grant_type=authorization_code`
  - `grant_type=token_exchange` (and RFC urn equivalent)
- Native SSO token exchange validations:
  - actor token type must be `urn:openid:params:token-type:device-secret`
  - actor token (device secret) signature/expiry validation
  - `id_token` signature validation
  - `ds_hash` binding check between `id_token` and `device_secret`
  - `sid` validation against persisted session
  - source session must include `device_sso`
  - `cnf.jkt` in `device_secret` must match current DPoP thumbprint (`DPoP-JKT` header)
  - second-app requested scope must be subset of first-app granted scope
  - reject `token_exchange` if `device_sso` scope is requested

## Run

```bash
go run /home/runner/work/MOsip2/MOsip2/cmd/esignet/main.go
```

Optional env vars:

- `ESIGNET_ISSUER` (default: `http://localhost:8080`)
- `ESIGNET_SIGNING_SECRET` (default: development-only fallback)

## Test

```bash
cd /home/runner/work/MOsip2/MOsip2
go test ./...
```

## Notes

This repository started empty, so the implementation is a focused baseline server to satisfy Native SSO core backend behavior from scratch, with in-memory stores and test coverage for critical success/failure paths.
