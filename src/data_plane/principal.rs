//! Who sent the request, decided before the path is examined.

use std::net::{IpAddr, SocketAddr};

use http::HeaderMap;
use http::header::AUTHORIZATION;

use crate::audit::{Principal, PrincipalKind};
use crate::provider::anthropic::X_API_KEY;
use crate::registry::Registry;
use crate::secret::Role;

/// IPv4 `127.0.0.0/8`, IPv6 `::1`, and IPv4-mapped `::ffff:127.0.0.0/104`.
pub fn is_loopback_peer(peer: SocketAddr) -> bool {
    match peer.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// At most one of the two credential headers, exactly one value.
pub enum Presented {
    None,
    One(String),
    Malformed,
}

pub fn presented_credential(headers: &HeaderMap) -> Presented {
    let bearer: Vec<&str> = headers
        .get_all(AUTHORIZATION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let key: Vec<&str> = headers
        .get_all(X_API_KEY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    match (bearer.as_slice(), key.as_slice()) {
        ([], []) => Presented::None,
        ([one], []) => match one
            .strip_prefix("Bearer ")
            .or_else(|| one.strip_prefix("bearer "))
        {
            Some(secret) if !secret.is_empty() => Presented::One(secret.to_string()),
            _ => Presented::Malformed,
        },
        ([], [one]) if !one.is_empty() => Presented::One((*one).to_string()),
        _ => Presented::Malformed,
    }
}

/// Whether a presented value carries one of this server's secret prefixes.
/// Anything else — Claude Code's own saved login, sent as the bearer when no
/// gateway credential overrides it — is not ours.
fn is_own_secret(value: &str) -> bool {
    [
        Role::ClientSecret,
        Role::OperatorSecret,
        Role::EnrollmentCode,
    ]
    .iter()
    .any(|role| value.starts_with(role.prefix()))
}

/// Exactly one principal, or none. The base-URL data plane is
/// v1-style: a loopback caller presenting no credential of ours is the
/// loopback operator — its Claude Code login is not a pool credential and the
/// pool drops it upstream. A presented credential of ours — loopback or
/// remote — resolves against the registry (operator slot first, then active
/// client entries); an unknown or malformed one is refused, never promoted.
/// The bootstrap exception: while no client and no operator secret exist, a
/// loopback caller is the loopback operator whatever it presents.
pub fn resolve(registry: &Registry, peer: SocketAddr, headers: &HeaderMap) -> Option<Principal> {
    let loopback = is_loopback_peer(peer);
    if loopback && registry.is_bootstrap() {
        return Some(Principal {
            kind: PrincipalKind::Loopback,
            id: None,
        });
    }
    let presented = match presented_credential(headers) {
        Presented::One(secret) if loopback && !is_own_secret(&secret) => Presented::None,
        presented => presented,
    };
    match presented {
        Presented::None if loopback => Some(Principal {
            kind: PrincipalKind::Loopback,
            id: None,
        }),
        Presented::None | Presented::Malformed => None,
        Presented::One(secret) => {
            if registry.operator_by_secret(&secret) {
                return Some(Principal {
                    kind: PrincipalKind::Operator,
                    id: None,
                });
            }
            registry.client_by_secret(&secret).map(|id| Principal {
                kind: PrincipalKind::Client,
                id: Some(id),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use time::OffsetDateTime;

    fn peer(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 4000)
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    #[test]
    fn loopback_is_the_peer_address_only() {
        assert!(is_loopback_peer(peer("127.0.0.1")));
        assert!(is_loopback_peer(peer("127.42.0.1")));
        assert!(is_loopback_peer(peer("::1")));
        assert!(is_loopback_peer(peer("::ffff:127.0.0.1")));
        assert!(!is_loopback_peer(peer("10.0.0.5")));
    }

    #[test]
    fn a_presented_credential_parses_as_one_value_or_malforms() {
        let mut h = HeaderMap::new();
        assert!(matches!(presented_credential(&h), Presented::None));
        h.insert(AUTHORIZATION, HeaderValue::from_static("Bearer jsc2_x"));
        assert!(matches!(presented_credential(&h), Presented::One(_)));
        h.clear();
        h.insert(X_API_KEY, HeaderValue::from_static("jsc2_x"));
        assert!(matches!(presented_credential(&h), Presented::One(_)));
        h.clear();
        h.insert(AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert!(matches!(presented_credential(&h), Presented::Malformed));
        h.clear();
        h.insert(AUTHORIZATION, HeaderValue::from_static("Bearer jsc2_x"));
        h.insert(X_API_KEY, HeaderValue::from_static("jsc2_x"));
        assert!(matches!(presented_credential(&h), Presented::Malformed));
    }

    #[test]
    fn the_bootstrap_exception_promotes_only_a_loopback_peer() {
        let registry = Registry::default();
        let mut h = HeaderMap::new();
        assert_eq!(
            resolve(&registry, peer("127.0.0.1"), &h).unwrap().kind,
            PrincipalKind::Loopback
        );
        h.insert(AUTHORIZATION, HeaderValue::from_static("Bearer anything"));
        assert_eq!(
            resolve(&registry, peer("127.0.0.1"), &h).unwrap().kind,
            PrincipalKind::Loopback
        );
        assert!(resolve(&registry, peer("10.0.0.5"), &h).is_none());
        h.clear();
        assert!(resolve(&registry, peer("10.0.0.5"), &h).is_none());
    }

    #[test]
    fn after_enrollment_credentials_resolve_by_role_or_refuse() {
        let mut registry = Registry::default();
        let operator = registry.provision_operator_secret(now());
        let (code, _) = registry.issue("mac", "Mac", now(), 60).expect("issue");
        let (_, client) = registry.claim("mac", &code, now()).expect("claim");
        let bearer = |value: &str| {
            let mut h = HeaderMap::new();
            h.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {value}")).unwrap(),
            );
            h
        };
        // No credential from loopback is the loopback operator (v1-style:
        // the tokenless base-URL caller); a presented credential of ours —
        // even from loopback — resolves against the registry.
        assert_eq!(
            resolve(&registry, peer("127.0.0.1"), &HeaderMap::new())
                .unwrap()
                .kind,
            PrincipalKind::Loopback
        );
        // Claude Code's own saved login is not ours: from loopback it counts
        // as no credential, from anywhere else it is refused.
        let own_login = bearer("sk-ant-oat01-engineer");
        assert_eq!(
            resolve(&registry, peer("127.0.0.1"), &own_login)
                .unwrap()
                .kind,
            PrincipalKind::Loopback
        );
        assert!(resolve(&registry, peer("10.0.0.5"), &own_login).is_none());
        // Each secret resolves to its own principal.
        let remote = resolve(&registry, peer("10.0.0.5"), &bearer(&operator)).unwrap();
        assert_eq!(remote.kind, PrincipalKind::Operator);
        let enrolled = resolve(&registry, peer("10.0.0.5"), &bearer(&client)).unwrap();
        assert_eq!(enrolled.kind, PrincipalKind::Client);
        assert_eq!(enrolled.id.as_deref(), Some("mac"));
        // Unknown, malformed and empty credentials are refused, never
        // promoted — loopback included.
        assert!(resolve(&registry, peer("127.0.0.1"), &bearer("jsc2_nope")).is_none());
        assert!(resolve(&registry, peer("10.0.0.5"), &bearer("jsc2_nope")).is_none());
        assert!(resolve(&registry, peer("10.0.0.5"), &bearer("jsc2_unknown")).is_none());
        let mut malformed = HeaderMap::new();
        malformed.insert(AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert!(resolve(&registry, peer("10.0.0.5"), &malformed).is_none());
        // The enrollment code is not a credential (it authorises
        // nothing but its own claim).
        let (pending_code, _) = registry.issue("pend", "Pending", now(), 60).expect("issue");
        assert!(resolve(&registry, peer("10.0.0.5"), &bearer(&pending_code)).is_none());
    }
}
