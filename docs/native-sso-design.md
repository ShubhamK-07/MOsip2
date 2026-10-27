# Native SSO Design (MOsip2 Baseline)

## Scope
This from-scratch baseline implements core backend behavior for OpenID Connect Native SSO patterns in a minimal Go service.

## Components
- `/oauth/token` endpoint for authorization code and token exchange grants.
- In-memory client registry with `allowed_authorization_scopes` semantics.
- In-memory session store keyed by `sid`.
- Device Secret Provider interface with HMAC-JWT implementation.

## Authorization Code + device_sso
1. Validate client and requested scopes against allowed authorization scopes.
2. If `device_sso` is present, ensure the client is explicitly entitled for it.
3. Generate signed `device_secret` including: `cnf.jkt`, `auth_id`, `exp`, `client_id`, `scope`, `acr`, `claims`, `iss`.
4. Embed `device_secret` and `ds_hash` into `id_token`.
5. Return `access_token`, `id_token`, and `device_secret`.

## Token Exchange (Silent Child App Login)
1. Enforce grant type `token_exchange` and `actor_token_type=urn:openid:params:token-type:device-secret`.
2. Reject if requested scope includes `device_sso`.
3. Validate actor token (`device_secret`) and subject token (`id_token`).
4. Validate binding checks:
   - `id_token.ds_hash == SHA-256(device_secret)`
   - `sid` exists and maps to a valid session
   - source session was created with `device_sso`
   - `device_secret.cnf.jkt == DPoP-JKT` request header
5. Enforce child-app eligibility (`allowed_authorization_scopes` contains `device_sso`).
6. Enforce requested scope subset of source session scope.
7. Optional bonus behavior: if configured, scope differences trigger `interaction_required` for re-consent.

## Security Notes
- This baseline uses HMAC signing for simplicity; production should use asymmetric signing, key rotation, secure key storage, real DPoP proof verification, and durable persistence.
