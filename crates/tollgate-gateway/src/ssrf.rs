//! `architecture.md` §10 SSRF steps 1 and 2: resolve every hostname ourselves and reject if any
//! resolved address lands in a disallowed range. This is necessary but not sufficient on its own —
//! step 3 (pinning the connection to the validated address) is Task 4.3, and is the real defence
//! against a DNS-rebinding time-of-check-to-time-of-use bypass of the checks in this file.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The one flag that must never be `true` in a deployed config: it exists purely so the local mock
/// upstream (`127.0.0.1:9000`) is reachable during development and tests. Default is unset/false.
const ALLOW_LOOPBACK_ENV: &str = "TOLLGATE_ALLOW_LOOPBACK_UPSTREAM";

fn loopback_allowed() -> bool {
    std::env::var(ALLOW_LOOPBACK_ENV)
        .map(|v| v == "true")
        .unwrap_or(false)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SsrfError {
    #[error("host resolves to a private (RFC 1918) address: {0}")]
    PrivateNetwork(IpAddr),
    #[error("host resolves to a loopback address: {0}")]
    Loopback(IpAddr),
    #[error("host resolves to a link-local address: {0}")]
    LinkLocal(IpAddr),
    #[error("host resolves to the cloud metadata endpoint: {0}")]
    CloudMetadata(IpAddr),
    #[error("host resolves to a unique-local ipv6 address: {0}")]
    UniqueLocalIpv6(IpAddr),
    #[error("host resolves to an unspecified/this-network address: {0}")]
    Unspecified(IpAddr),
    #[error("host resolves to a multicast address: {0}")]
    Multicast(IpAddr),
    #[error("host resolves to a carrier-grade NAT (RFC 6598) address: {0}")]
    Cgnat(IpAddr),
    #[error("unsupported url scheme: {0}")]
    UnsupportedScheme(String),
    #[error("url must not contain credentials")]
    CredentialsNotAllowed,
    #[error("port {0} is not allowed")]
    PortNotAllowed(u16),
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[error("dns resolution failed: {0}")]
    ResolutionFailed(String),
    #[error("host did not resolve to any address")]
    NoAddresses,
}

/// Resolves `host:port` through the system resolver (documented as needing to be a public
/// resolver, not an internal one, in deployment) and rejects if any resolved address is
/// disallowed. Returns every validated address; the caller picks one to dial (Task 4.3).
pub async fn resolve_and_validate(host: &str, port: u16) -> Result<Vec<SocketAddr>, SsrfError> {
    // IPv6 literals need bracketing to form a valid "host:port" lookup query; a bare domain or
    // IPv4 literal does not.
    let query = if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&query)
        .await
        .map_err(|e| SsrfError::ResolutionFailed(e.to_string()))?
        .collect();

    if addrs.is_empty() {
        return Err(SsrfError::NoAddresses);
    }

    let allow_loopback = loopback_allowed();

    for addr in &addrs {
        validate_ip(addr.ip(), allow_loopback)?;
    }

    Ok(addrs)
}

/// The address-level check, split out from resolution so it can be exercised directly against a
/// hand-built address list — including a deliberate mix of public and private addresses — without
/// depending on what a real DNS server happens to return.
fn validate_ip(ip: IpAddr, allow_loopback: bool) -> Result<(), SsrfError> {
    match ip {
        IpAddr::V4(v4) => validate_ipv4(v4, allow_loopback),
        IpAddr::V6(v6) => {
            // Checked after unmapping: an IPv4-mapped IPv6 address (::ffff:0:0/96) is validated
            // against the IPv4 rules for the address it maps to, not against a separate blanket
            // "reject all mapped addresses" rule.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return validate_ipv4(mapped, allow_loopback);
            }
            validate_ipv6(v6)
        }
    }
}

fn validate_ipv4(v4: Ipv4Addr, allow_loopback: bool) -> Result<(), SsrfError> {
    let ip = IpAddr::V4(v4);

    if v4 == Ipv4Addr::new(169, 254, 169, 254) {
        return Err(SsrfError::CloudMetadata(ip));
    }
    if v4.is_loopback() {
        if allow_loopback {
            return Ok(());
        }
        return Err(SsrfError::Loopback(ip));
    }
    if is_rfc1918(v4) {
        return Err(SsrfError::PrivateNetwork(ip));
    }
    if v4.is_link_local() {
        return Err(SsrfError::LinkLocal(ip));
    }
    // The whole 0.0.0.0/8 "this network" block, not just the single unspecified address:
    // std's `is_unspecified()` only matches 0.0.0.0 exactly.
    if v4.octets()[0] == 0 {
        return Err(SsrfError::Unspecified(ip));
    }
    if v4.is_multicast() {
        return Err(SsrfError::Multicast(ip));
    }
    if is_cgnat(v4) {
        return Err(SsrfError::Cgnat(ip));
    }

    Ok(())
}

fn validate_ipv6(v6: Ipv6Addr) -> Result<(), SsrfError> {
    let ip = IpAddr::V6(v6);

    if v6.is_loopback() {
        return Err(SsrfError::Loopback(ip));
    }
    if is_link_local_v6(v6) {
        return Err(SsrfError::LinkLocal(ip));
    }
    if is_unique_local_v6(v6) {
        return Err(SsrfError::UniqueLocalIpv6(ip));
    }
    if v6.is_unspecified() {
        return Err(SsrfError::Unspecified(ip));
    }
    if v6.is_multicast() {
        return Err(SsrfError::Multicast(ip));
    }

    Ok(())
}

/// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
fn is_rfc1918(v4: Ipv4Addr) -> bool {
    let [a, b, ..] = v4.octets();
    a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168)
}

/// 100.64.0.0/10.
fn is_cgnat(v4: Ipv4Addr) -> bool {
    let [a, b, ..] = v4.octets();
    a == 100 && (64..=127).contains(&b)
}

/// fe80::/10.
fn is_link_local_v6(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

/// fc00::/7.
fn is_unique_local_v6(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

/// Reject non-http/https schemes and any URL with embedded credentials or a non-standard port
/// outside 80/443, unless explicitly allowed by config. Returns the host and port to resolve.
/// This runs before DNS resolution, since scheme/credential/port checks are cheap and don't need
/// a network round trip.
///
/// The only config this MVP has for relaxing the port rule is `ALLOW_LOOPBACK_ENV`: its whole
/// purpose (Task 4.1) is making the local mock upstream on `127.0.0.1:9000` reachable, and a
/// flag that permits the loopback address but still blocks its non-standard port would not
/// achieve that. The relaxation is scoped to the two loopback literals, not to arbitrary hosts.
pub fn validate_url(raw: &str) -> Result<(String, u16), SsrfError> {
    let url = url::Url::parse(raw).map_err(|e| SsrfError::InvalidUrl(e.to_string()))?;

    match url.scheme() {
        "http" | "https" => {}
        other => return Err(SsrfError::UnsupportedScheme(other.to_string())),
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err(SsrfError::CredentialsNotAllowed);
    }

    let host = url
        .host_str()
        .ok_or_else(|| SsrfError::InvalidUrl("url has no host".to_string()))?
        .to_string();

    let default_port = if url.scheme() == "https" { 443 } else { 80 };
    let port = url.port().unwrap_or(default_port);
    let is_loopback_literal = host == "127.0.0.1" || host == "::1";
    if port != 80 && port != 443 && !(is_loopback_literal && loopback_allowed()) {
        return Err(SsrfError::PortNotAllowed(port));
    }

    Ok((host, port))
}

#[cfg(test)]
mod denylist {
    use super::*;
    use tokio::sync::Mutex;

    /// `ALLOW_LOOPBACK_ENV` is process-global mutable state; cargo runs test functions
    /// within a binary concurrently by default, so the three tests below that set or
    /// rely on its absence must not interleave.
    static ENV_LOCK: Mutex<()> = Mutex::const_new(());

    async fn assert_rejected(host: &str) -> SsrfError {
        resolve_and_validate(host, 80)
            .await
            .expect_err(&format!("{host} should be rejected"))
    }

    async fn assert_accepted(host: &str) {
        resolve_and_validate(host, 80)
            .await
            .unwrap_or_else(|e| panic!("{host} should be accepted, got {e}"));
    }

    #[tokio::test]
    async fn rfc1918_is_rejected() {
        assert!(matches!(
            assert_rejected("10.0.0.1").await,
            SsrfError::PrivateNetwork(_)
        ));
    }

    #[tokio::test]
    async fn loopback_is_rejected_by_default() {
        let _guard = ENV_LOCK.lock().await;
        unsafe { std::env::remove_var(ALLOW_LOOPBACK_ENV) };
        assert!(matches!(
            assert_rejected("127.0.0.1").await,
            SsrfError::Loopback(_)
        ));
    }

    #[tokio::test]
    async fn cloud_metadata_is_rejected() {
        assert!(matches!(
            assert_rejected("169.254.169.254").await,
            SsrfError::CloudMetadata(_)
        ));
    }

    #[tokio::test]
    async fn ipv6_loopback_is_rejected() {
        assert!(matches!(assert_rejected("::1").await, SsrfError::Loopback(_)));
    }

    #[tokio::test]
    async fn ipv6_unique_local_is_rejected() {
        assert!(matches!(
            assert_rejected("fc00::1").await,
            SsrfError::UniqueLocalIpv6(_)
        ));
    }

    #[tokio::test]
    async fn ipv4_mapped_ipv6_loopback_is_rejected() {
        let _guard = ENV_LOCK.lock().await;
        unsafe { std::env::remove_var(ALLOW_LOOPBACK_ENV) };
        assert!(matches!(
            assert_rejected("::ffff:127.0.0.1").await,
            SsrfError::Loopback(_)
        ));
    }

    #[tokio::test]
    async fn cgnat_is_rejected() {
        assert!(matches!(assert_rejected("100.64.0.1").await, SsrfError::Cgnat(_)));
    }

    #[tokio::test]
    async fn unspecified_this_network_is_rejected() {
        assert!(matches!(
            assert_rejected("0.0.0.0").await,
            SsrfError::Unspecified(_)
        ));
    }

    #[tokio::test]
    async fn public_ipv4_addresses_are_accepted() {
        assert_accepted("1.1.1.1").await;
        assert_accepted("8.8.8.8").await;
    }

    #[test]
    fn a_mix_of_public_and_private_addresses_is_rejected() {
        // Built directly rather than via a real hostname: which addresses a DNS name resolves to
        // is not something a test should depend on. This exercises the exact rule the resolving
        // wrapper relies on — reject if *any* resolved address is disallowed.
        let mix = [
            "1.1.1.1".parse::<IpAddr>().unwrap(),
            "10.0.0.5".parse::<IpAddr>().unwrap(),
        ];
        let result = mix.iter().try_for_each(|ip| validate_ip(*ip, false));
        assert!(matches!(result, Err(SsrfError::PrivateNetwork(_))));
    }

    #[tokio::test]
    async fn loopback_is_accepted_when_the_env_flag_is_set() {
        let _guard = ENV_LOCK.lock().await;
        unsafe { std::env::set_var(ALLOW_LOOPBACK_ENV, "true") };
        let result = resolve_and_validate("127.0.0.1", 9000).await;
        unsafe { std::env::remove_var(ALLOW_LOOPBACK_ENV) };
        assert!(result.is_ok(), "expected loopback to be accepted, got {result:?}");
    }
}

#[cfg(test)]
mod url_validation {
    use super::*;

    #[test]
    fn rejects_non_http_schemes() {
        let err = validate_url("ftp://example.com/").unwrap_err();
        assert!(matches!(err, SsrfError::UnsupportedScheme(ref s) if s == "ftp"));
    }

    #[test]
    fn rejects_embedded_credentials() {
        let err = validate_url("http://user:pass@example.com/").unwrap_err();
        assert_eq!(err, SsrfError::CredentialsNotAllowed);
    }

    #[test]
    fn rejects_non_standard_ports() {
        let err = validate_url("http://example.com:8080/").unwrap_err();
        assert_eq!(err, SsrfError::PortNotAllowed(8080));
    }

    #[test]
    fn accepts_default_ports() {
        let (host, port) = validate_url("https://example.com/").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);

        let (host, port) = validate_url("http://example.com/").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn accepts_explicit_standard_ports() {
        let (_, port) = validate_url("http://example.com:80/").unwrap();
        assert_eq!(port, 80);
    }
}
