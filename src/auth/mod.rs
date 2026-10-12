//! Authentication module for zn Management API
//!
//! A token from `X-API-Key`, `Authorization: Bearer` or the `api_key` / `token`
//! query parameter is checked in this order:
//! 1. Legacy single API key (`ZN_API_KEY`): super-admin.
//! 2. Tenant API key, looked up in the TenantStore.
//! 3. JWT (HS256, signed with `ZN_JWT_SECRET`) carrying explicit claims:
//!    `roles` (lowercase `superadmin`, `admin`, `user`, `viewer` or `blocked`)
//!    and, for every role except `superadmin`, a tenant `namespace`.
//!
//! An invalid token gets 401; a valid JWT that grants no usable role gets 403.

use crate::tenants::{TenantContext, TenantRole, TenantStore};
use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Authentication state shared across handlers
#[derive(Clone)]
pub struct AuthConfig {
    /// Legacy API key for super-admin (backwards compatibility)
    pub api_key: Option<String>,
    /// Secret for JWT validation (None = JWT disabled)
    pub jwt_secret: Option<String>,
    /// Tenant store for multi-tenancy
    pub tenant_store: Option<Arc<TenantStore>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: Option<usize>,
    /// Roles granted to the token: superadmin, admin, user or viewer.
    pub roles: Option<Vec<String>>,
    /// Tenant namespace; required for every role except superadmin.
    #[serde(default)]
    pub namespace: Option<String>,
}

/// Namespace of the super-admin context. Reserved: tenant tokens cannot use it.
const GLOBAL_NAMESPACE: &str = "global";

/// Result of checking a bearer token as a JWT.
#[derive(Debug)]
enum JwtCheck {
    /// Bad signature, expired, or not a JWT at all.
    Invalid,
    /// Valid token that grants no usable role (carries the token's `sub`).
    NoRole(String),
    /// Valid token with an explicit role.
    Granted(TenantContext),
}

/// Strict role mapping for tokens: exact lowercase names only; anything else
/// grants nothing.
fn jwt_role(name: &str) -> Option<TenantRole> {
    match name {
        "superadmin" => Some(TenantRole::SuperAdmin),
        "admin" => Some(TenantRole::Admin),
        "user" => Some(TenantRole::User),
        "viewer" => Some(TenantRole::Viewer),
        "blocked" => Some(TenantRole::Blocked),
        _ => None,
    }
}

fn role_rank(role: TenantRole) -> u8 {
    match role {
        TenantRole::SuperAdmin => 4,
        TenantRole::Admin => 3,
        TenantRole::User => 2,
        TenantRole::Viewer => 1,
        TenantRole::Blocked => 0,
    }
}

/// A tenant namespace from a token is used as is: it must be non-empty, have
/// no whitespace or control characters, and must not be the reserved global
/// namespace (in any letter case).
fn valid_tenant_namespace(ns: &str) -> bool {
    !ns.is_empty()
        && ns.len() <= 128
        && !ns.chars().any(|c| c.is_whitespace() || c.is_control())
        && !ns.eq_ignore_ascii_case(GLOBAL_NAMESPACE)
}

/// Builds the request context from verified claims. Deny by default: the token
/// must name a known role, `blocked` wins over everything, the highest of the
/// remaining roles applies, and tenant roles need a valid tenant namespace.
fn context_from_claims(claims: &Claims) -> Option<TenantContext> {
    let roles: Vec<TenantRole> = claims
        .roles
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter_map(|r| jwt_role(r.as_str()))
        .collect();
    if roles.contains(&TenantRole::Blocked) {
        return None;
    }
    let role = roles.into_iter().max_by_key(|r| role_rank(*r))?;
    let namespace = match role {
        TenantRole::SuperAdmin => GLOBAL_NAMESPACE.to_string(),
        _ => claims
            .namespace
            .as_deref()
            .filter(|ns| valid_tenant_namespace(ns))?
            .to_string(),
    };
    Some(TenantContext {
        id: format!("jwt:{}", claims.sub),
        name: claims.sub.clone(),
        namespace,
        role,
    })
}

fn check_jwt(token: &str, secret: &str) -> JwtCheck {
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    let validation = Validation::new(Algorithm::HS256);
    match decode::<Claims>(token, &decoding_key, &validation) {
        Ok(data) => match context_from_claims(&data.claims) {
            Some(ctx) => JwtCheck::Granted(ctx),
            None => JwtCheck::NoRole(data.claims.sub),
        },
        Err(_) => JwtCheck::Invalid,
    }
}

impl AuthConfig {
    pub fn new(api_key: Option<String>, jwt_secret: Option<String>) -> Self {
        Self {
            api_key,
            jwt_secret,
            tenant_store: None,
        }
    }

    pub fn with_tenant_store(mut self, store: Arc<TenantStore>) -> Self {
        self.tenant_store = Some(store);
        self
    }

    /// Check if authentication is required
    pub fn is_auth_required(&self) -> bool {
        self.api_key.is_some() || self.jwt_secret.is_some() || self.tenant_store.is_some()
    }
}

/// Super-admin context for legacy API key
pub fn super_admin_context() -> TenantContext {
    TenantContext {
        id: "super-admin".to_string(),
        name: "Super Admin".to_string(),
        namespace: GLOBAL_NAMESPACE.to_string(),
        role: TenantRole::SuperAdmin,
    }
}

/// Authentication middleware supporting API Keys, JWTs, and Multi-Tenancy
pub async fn api_key_auth(mut request: Request, next: Next) -> Result<Response, StatusCode> {
    // Get auth config from request extensions
    let auth_config = request.extensions().get::<Arc<AuthConfig>>().cloned();

    let config = match auth_config {
        Some(c) => c,
        None => return Ok(next.run(request).await),
    };

    // If no auth is configured, allow all
    if !config.is_auth_required() {
        return Ok(next.run(request).await);
    }

    // Extract authorization token
    let auth_header = request
        .headers()
        .get("X-API-Key")
        .or_else(|| request.headers().get(header::AUTHORIZATION))
        .and_then(|v| v.to_str().ok());

    let token = if let Some(header_val) = auth_header {
        Some(header_val.trim_start_matches("Bearer ").trim().to_string())
    } else {
        // Fallback: Check query parameters (for SSE/WebSocket)
        request.uri().query().and_then(|query| {
            query.split('&').find_map(|pair| {
                let (key, val) = pair.split_once('=')?;
                if key == "api_key" || key == "token" {
                    Some(val.to_string())
                } else {
                    None
                }
            })
        })
    };

    match token {
        Some(token) => {
            // 1. Check against Legacy Super-Admin API Key
            if let Some(expected_key) = &config.api_key {
                if constant_time_compare(&token, expected_key) {
                    // Inject super-admin context
                    request.extensions_mut().insert(super_admin_context());
                    return Ok(next.run(request).await);
                }
            }

            // 2. Check against Tenant Store (Multi-Tenancy)
            if let Some(store) = &config.tenant_store {
                if let Ok(Some(tenant_ctx)) = store.find_by_api_key(&token) {
                    if tenant_ctx.role == TenantRole::Blocked {
                        tracing::warn!("Blocked tenant attempted access: {}", tenant_ctx.name);
                        return Err(StatusCode::FORBIDDEN);
                    }
                    // Inject tenant context into request
                    request.extensions_mut().insert(tenant_ctx);
                    return Ok(next.run(request).await);
                }
            }

            // 3. Try JWT validation: access comes only from explicit roles
            if let Some(secret) = &config.jwt_secret {
                match check_jwt(&token, secret) {
                    JwtCheck::Granted(ctx) => {
                        request.extensions_mut().insert(ctx);
                        return Ok(next.run(request).await);
                    }
                    JwtCheck::NoRole(sub) => {
                        tracing::warn!(sub = %sub, "JWT accepted but grants no usable role");
                        return Err(StatusCode::FORBIDDEN);
                    }
                    JwtCheck::Invalid => {}
                }
            }

            tracing::warn!("Failed authentication attempt with token provided");
            Err(StatusCode::UNAUTHORIZED)
        }
        None => {
            tracing::warn!("No authentication provided for protected resource");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// Constant-time string comparison to prevent timing attacks
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};

    const SECRET: &str = "test-secret-for-unit-tests-only";

    fn now() -> usize {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs() as usize
    }

    fn claims(roles: Option<Vec<&str>>, namespace: Option<&str>, exp: usize) -> Claims {
        Claims {
            sub: "ops@example.com".to_string(),
            exp,
            iat: Some(now()),
            roles: roles.map(|r| r.into_iter().map(String::from).collect()),
            namespace: namespace.map(String::from),
        }
    }

    fn token_with(alg: Algorithm, claims: &Claims) -> String {
        encode(
            &Header::new(alg),
            claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .expect("encode test token")
    }

    fn token(roles: Option<Vec<&str>>, namespace: Option<&str>, exp: usize) -> String {
        token_with(Algorithm::HS256, &claims(roles, namespace, exp))
    }

    fn granted(check: JwtCheck) -> TenantContext {
        match check {
            JwtCheck::Granted(ctx) => ctx,
            other => panic!("expected access, got {:?}", other),
        }
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("test", "test"));
        assert!(!constant_time_compare("test", "Test"));
    }

    #[test]
    fn jwt_without_roles_is_denied() {
        let t = token(None, Some("acme"), now() + 600);
        assert!(matches!(check_jwt(&t, SECRET), JwtCheck::NoRole(_)));
        let t = token(Some(vec![]), Some("acme"), now() + 600);
        assert!(matches!(check_jwt(&t, SECRET), JwtCheck::NoRole(_)));
    }

    #[test]
    fn jwt_with_unknown_role_is_denied() {
        let t = token(Some(vec!["root"]), Some("acme"), now() + 600);
        assert!(matches!(check_jwt(&t, SECRET), JwtCheck::NoRole(_)));
    }

    #[test]
    fn jwt_with_valid_tenant_role_is_scoped() {
        let ctx = granted(check_jwt(
            &token(Some(vec!["viewer"]), Some("acme"), now() + 600),
            SECRET,
        ));
        assert_eq!(ctx.role, TenantRole::Viewer);
        assert_eq!(ctx.namespace, "acme");
        assert!(!ctx.is_super_admin());
    }

    #[test]
    fn jwt_tenant_role_needs_a_namespace() {
        let t = token(Some(vec!["admin"]), None, now() + 600);
        assert!(matches!(check_jwt(&t, SECRET), JwtCheck::NoRole(_)));
        let t = token(Some(vec!["admin"]), Some("  "), now() + 600);
        assert!(matches!(check_jwt(&t, SECRET), JwtCheck::NoRole(_)));
    }

    #[test]
    fn jwt_superadmin_only_when_explicit() {
        let ctx = granted(check_jwt(
            &token(Some(vec!["superadmin"]), None, now() + 600),
            SECRET,
        ));
        assert!(ctx.is_super_admin());
        assert_eq!(ctx.namespace, "global");
    }

    #[test]
    fn jwt_highest_role_applies_and_blocked_wins() {
        let ctx = granted(check_jwt(
            &token(Some(vec!["viewer", "admin"]), Some("acme"), now() + 600),
            SECRET,
        ));
        assert_eq!(ctx.role, TenantRole::Admin);
        let t = token(
            Some(vec!["blocked", "superadmin"]),
            Some("acme"),
            now() + 600,
        );
        assert!(matches!(check_jwt(&t, SECRET), JwtCheck::NoRole(_)));
    }

    #[test]
    fn expired_or_foreign_jwt_is_invalid() {
        // Past the default 60 s leeway.
        let t = token(Some(vec!["superadmin"]), None, now() - 3600);
        assert!(matches!(check_jwt(&t, SECRET), JwtCheck::Invalid));
        let t = token(Some(vec!["superadmin"]), None, now() + 600);
        assert!(matches!(check_jwt(&t, "another-secret"), JwtCheck::Invalid));
        assert!(matches!(check_jwt("not-a-jwt", SECRET), JwtCheck::Invalid));
    }

    #[test]
    fn only_hs256_is_accepted() {
        let c = claims(Some(vec!["superadmin"]), None, now() + 600);
        for alg in [Algorithm::HS384, Algorithm::HS512] {
            let t = token_with(alg, &c);
            assert!(
                matches!(check_jwt(&t, SECRET), JwtCheck::Invalid),
                "{alg:?}"
            );
        }

        // Unsigned token: {"alg":"none"} and an empty signature.
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&c).unwrap());
        for t in [
            format!("{header}.{payload}."),
            format!("{header}.{payload}"),
        ] {
            assert!(matches!(check_jwt(&t, SECRET), JwtCheck::Invalid));
        }
    }

    #[test]
    fn blocked_alone_is_denied() {
        let t = token(Some(vec!["blocked"]), Some("acme"), now() + 600);
        assert!(matches!(check_jwt(&t, SECRET), JwtCheck::NoRole(_)));
    }

    #[test]
    fn role_names_are_exact_lowercase() {
        for role in ["SuperAdmin", "SUPERADMIN", "Admin", "super_admin", " admin"] {
            let t = token(Some(vec![role]), Some("acme"), now() + 600);
            assert!(
                matches!(check_jwt(&t, SECRET), JwtCheck::NoRole(_)),
                "{role:?}"
            );
        }
    }

    #[test]
    fn tenant_namespace_must_be_clean_and_not_global() {
        for ns in ["  acme  ", "ac me", "acme\n", "global", "GLOBAL", "Global"] {
            let t = token(Some(vec!["admin"]), Some(ns), now() + 600);
            assert!(
                matches!(check_jwt(&t, SECRET), JwtCheck::NoRole(_)),
                "{ns:?}"
            );
        }
        // A superadmin always gets the global namespace, whatever the claim says.
        let ctx = granted(check_jwt(
            &token(Some(vec!["superadmin"]), Some("acme"), now() + 600),
            SECRET,
        ));
        assert_eq!(ctx.namespace, GLOBAL_NAMESPACE);
    }

    // --- Middleware through a real router and HTTP server ---

    use axum::{routing::get, Extension, Router};
    use rusqlite::Connection;
    use std::sync::Mutex;

    const LEGACY_KEY: &str = "legacy-key-for-unit-tests-only";
    const TENANT_KEY: &str = "tenant-key-for-unit-tests-only";
    const BLOCKED_KEY: &str = "blocked-key-for-unit-tests-only";

    async fn whoami(Extension(t): Extension<TenantContext>) -> String {
        format!("{}:{}", t.role.as_str(), t.namespace)
    }

    /// Serves `/whoami` behind the auth middleware, configured like the
    /// management API, and returns its URL.
    async fn serve(jwt_as_tenant_key: &str) -> String {
        let conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        let store = Arc::new(TenantStore::new(Arc::clone(&conn)).unwrap());
        store.create_tenant("acme", "acme", TENANT_KEY).unwrap();
        store.create_tenant("blk", "blk", BLOCKED_KEY).unwrap();
        // The same strings as the legacy key and as a valid JWT, registered as
        // tenant keys, show which check runs first.
        store.create_tenant("dup", "dup", LEGACY_KEY).unwrap();
        store
            .create_tenant("jwtkey", "jwtkey", jwt_as_tenant_key)
            .unwrap();
        conn.lock()
            .unwrap()
            .execute(
                "UPDATE tenants SET role = 'blocked' WHERE namespace = 'blk'",
                [],
            )
            .unwrap();

        let config = Arc::new(
            AuthConfig::new(Some(LEGACY_KEY.to_string()), Some(SECRET.to_string()))
                .with_tenant_store(store),
        );
        let app = Router::new()
            .route("/whoami", get(whoami))
            .layer(axum::middleware::from_fn(api_key_auth))
            .layer(Extension(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/whoami")
    }

    async fn call(url: &str, header: Option<(&str, String)>) -> (u16, String) {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let mut req = client.get(url);
        if let Some((name, value)) = header {
            req = req.header(name, value);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        (status, resp.text().await.unwrap())
    }

    fn bearer(t: &str) -> Option<(&'static str, String)> {
        Some(("Authorization", format!("Bearer {t}")))
    }

    #[tokio::test]
    async fn middleware_status_codes_and_check_order() {
        let superadmin_jwt = token(Some(vec!["superadmin"]), None, now() + 600);
        let url = serve(&superadmin_jwt).await;

        // 401: nothing, garbage, expired or foreign tokens.
        assert_eq!(call(&url, None).await.0, 401);
        assert_eq!(call(&url, bearer("not-a-key")).await.0, 401);
        let expired = token(Some(vec!["viewer"]), Some("acme"), now() - 3600);
        assert_eq!(call(&url, bearer(&expired)).await.0, 401);
        let hs512 = token_with(
            Algorithm::HS512,
            &claims(Some(vec!["superadmin"]), None, now() + 600),
        );
        assert_eq!(call(&url, bearer(&hs512)).await.0, 401);

        // 403: blocked tenant, valid JWT without a usable role.
        assert_eq!(call(&url, bearer(BLOCKED_KEY)).await.0, 403);
        let no_role = token(None, Some("acme"), now() + 600);
        assert_eq!(call(&url, bearer(&no_role)).await.0, 403);
        let global_ns = token(Some(vec!["admin"]), Some("global"), now() + 600);
        assert_eq!(call(&url, bearer(&global_ns)).await.0, 403);

        // 200 with the expected context, from a header or the query string.
        assert_eq!(
            call(&url, bearer(TENANT_KEY)).await,
            (200, "user:acme".to_string())
        );
        assert_eq!(
            call(&url, Some(("X-API-Key", TENANT_KEY.to_string()))).await,
            (200, "user:acme".to_string())
        );
        assert_eq!(
            call(&format!("{url}?token={TENANT_KEY}"), None).await,
            (200, "user:acme".to_string())
        );
        let viewer = token(Some(vec!["viewer"]), Some("acme"), now() + 600);
        assert_eq!(
            call(&url, bearer(&viewer)).await,
            (200, "viewer:acme".to_string())
        );

        // Order: legacy key, then tenant keys, then JWT.
        assert_eq!(
            call(&url, bearer(LEGACY_KEY)).await,
            (200, "superadmin:global".to_string())
        );
        assert_eq!(
            call(&url, bearer(&superadmin_jwt)).await,
            (200, "user:jwtkey".to_string())
        );
    }
}
