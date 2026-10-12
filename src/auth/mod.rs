//! Authentication module for zn Management API
//!
//! Provides multi-modal authentication:
//! 1. API Key (X-API-Key or Bearer) - looked up in TenantStore
//! 2. JWT (HS256, signed by the trusted secret) carrying explicit roles
//! 3. Legacy single API key (super-admin fallback)

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

/// Result of checking a bearer token as a JWT.
#[derive(Debug)]
enum JwtCheck {
    /// Bad signature, expired, or not a JWT at all.
    Invalid,
    /// Valid token that grants no usable role.
    NoRole,
    /// Valid token with an explicit role.
    Granted(TenantContext),
}

/// Strict role mapping for tokens: unknown names grant nothing.
fn jwt_role(name: &str) -> Option<TenantRole> {
    match name.to_ascii_lowercase().as_str() {
        "superadmin" | "super_admin" => Some(TenantRole::SuperAdmin),
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

/// Builds the request context from verified claims. Deny by default: the token
/// must name a known role, `blocked` wins over everything, the highest of the
/// remaining roles applies, and tenant roles need a namespace.
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
        TenantRole::SuperAdmin => "global".to_string(),
        _ => claims
            .namespace
            .as_deref()
            .map(str::trim)
            .filter(|ns| !ns.is_empty())?
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
            None => JwtCheck::NoRole,
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
        namespace: "global".to_string(),
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
                    JwtCheck::NoRole => {
                        tracing::warn!("JWT accepted but grants no usable role");
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

    fn token(roles: Option<Vec<&str>>, namespace: Option<&str>, exp: usize) -> String {
        let claims = Claims {
            sub: "ops@example.com".to_string(),
            exp,
            iat: Some(now()),
            roles: roles.map(|r| r.into_iter().map(String::from).collect()),
            namespace: namespace.map(String::from),
        };
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .expect("encode test token")
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
        assert!(matches!(check_jwt(&t, SECRET), JwtCheck::NoRole));
        let t = token(Some(vec![]), Some("acme"), now() + 600);
        assert!(matches!(check_jwt(&t, SECRET), JwtCheck::NoRole));
    }

    #[test]
    fn jwt_with_unknown_role_is_denied() {
        let t = token(Some(vec!["root"]), Some("acme"), now() + 600);
        assert!(matches!(check_jwt(&t, SECRET), JwtCheck::NoRole));
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
        assert!(matches!(check_jwt(&t, SECRET), JwtCheck::NoRole));
        let t = token(Some(vec!["admin"]), Some("  "), now() + 600);
        assert!(matches!(check_jwt(&t, SECRET), JwtCheck::NoRole));
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
        assert!(matches!(check_jwt(&t, SECRET), JwtCheck::NoRole));
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
}
