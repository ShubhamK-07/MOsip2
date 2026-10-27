# Native SSO API Notes

## POST /oauth/token

### Authorization Code Flow (Super App)
Form fields:
- `grant_type=authorization_code`
- `client_id`
- `scope` (include `device_sso` to enable Native SSO bootstrap)
- `auth_id`
- `acr`
- `sid` (optional)
- `cnf_jkt` (required)

Success response (200):
- `access_token`
- `id_token`
- `scope`
- `device_secret` (only when `device_sso` is requested)

### Token Exchange Flow (Child App)
Form fields:
- `grant_type=token_exchange` (or RFC URN variant)
- `client_id`
- `actor_token_type=urn:openid:params:token-type:device-secret`
- `actor_token` (device secret)
- `subject_token` (id token from super app)
- `scope` (must be subset; must not contain `device_sso`)

Required header:
- `DPoP-JKT` matching `actor_token.cnf.jkt`

Success response (200):
- `access_token`
- `id_token`
- `scope`

Error patterns:
- `invalid_scope` for non-subset scope, disallowed scope, or use of `device_sso` in token exchange.
- `invalid_grant` for invalid/expired device secret, id token mismatch, or invalid session.
- `interaction_required` (403, optional) when re-consent is required due to scope change.
