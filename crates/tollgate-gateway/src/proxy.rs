//! `architecture.md` §10 SSRF steps 3 and 5: the pinned-IP connector and the streaming reverse
//! proxy built over it.
//!
//! Step 3 is the point of this module. Task 4.1/4.2 validate a URL's IP before it is used; without
//! pinning, that check and the actual connection are two separate operations an attacker can split
//! with a DNS record that answers differently the second time (rebinding). The connector below
//! resolves and validates exactly once per call and dials the resulting `SocketAddr` directly,
//! never handing the hostname back to the resolver, so there is no window between check and use.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use http::Uri;
use http_body_util::BodyDataStream;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpStream;
use tower::Service;

use tollgate_core::metrics::StageTimer;
use tollgate_core::Provider;

use crate::ssrf;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A `tower::Service<Uri>` that resolves and validates a destination exactly once, then dials the
/// first validated address directly. The `Uri` handed to `call` still carries the original
/// hostname (and scheme), which is what the wrapping `HttpsConnector` uses for the TLS SNI and
/// what the outer client uses for the `Host` header — only the TCP dial itself uses the resolved
/// `SocketAddr` instead of the hostname.
#[derive(Debug, Clone, Copy, Default)]
pub struct PinnedConnector;

impl Service<Uri> for PinnedConnector {
    type Response = TokioIo<TcpStream>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        Box::pin(async move {
            dial(&uri, |host, port| async move {
                ssrf::resolve_and_validate(&host, port).await
            })
            .await
        })
    }
}

/// The connect discipline `architecture.md` §10 step 3 exists for: resolve `uri`'s host exactly
/// once via `resolve`, then dial the resulting `SocketAddr` directly — never handing the hostname
/// back to any resolver a second time. If DNS were to answer differently a moment later (the
/// rebinding attack this defends against), it can't matter, because nothing after this point ever
/// asks again.
///
/// Generic over the resolver so the discipline itself — one resolution, then a direct dial of its
/// result — is provable in a test with a resolver that deliberately answers differently than a
/// real one would (see `rebinding` below), independent of `ssrf::resolve_and_validate`'s own
/// denylist logic, which Task 4.1 already covers exhaustively.
async fn dial<F, Fut>(uri: &Uri, resolve: F) -> Result<TokioIo<TcpStream>, BoxError>
where
    F: FnOnce(String, u16) -> Fut,
    Fut: Future<Output = Result<Vec<std::net::SocketAddr>, ssrf::SsrfError>>,
{
    let host = uri
        .host()
        .ok_or_else(|| -> BoxError { "destination uri has no host".into() })?
        .to_string();
    let default_port = if uri.scheme_str() == Some("https") { 443 } else { 80 };
    let port = uri.port_u16().unwrap_or(default_port);

    let addrs = resolve(host, port).await?;
    // "picks the first validated SocketAddr, and dials that address directly": resolution
    // already rejected the whole set if any address were disallowed, so any member is
    // safe to use; the first is as good as any.
    let addr = *addrs.first().ok_or::<BoxError>("no validated address".into())?;

    let stream = TcpStream::connect(addr).await?;
    Ok(TokioIo::new(stream))
}

pub type ProxyClient = Client<HttpsConnector<PinnedConnector>, Body>;

/// Builds the one connection-pooled client this gateway process uses for every upstream call.
/// `architecture.md` §10 step 3 is the pinning in `PinnedConnector`; this just layers TLS (with
/// SNI taken from the destination `Uri`, i.e. the original hostname, by `hyper-rustls`'s default
/// resolver) and HTTP/1.1 on top of it.
pub fn build_client() -> ProxyClient {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(PinnedConnector);

    Client::builder(TokioExecutor::new()).build(https)
}

/// Failure to proxy, distinguishing a timeout (the provider's configured `timeout_ms` elapsed)
/// from every other connector/protocol failure, since the two map to different status codes.
#[derive(Debug)]
pub enum ProxyError {
    Timeout,
    Upstream(BoxError),
}

const X_PAYMENT: &str = "x-payment";
const X_TOLLGATE_PREFIX: &str = "x-tollgate-";

/// Request headers that must never reach the upstream: the payment header and any
/// Tollgate-internal header (neither is upstream's business), `Host` (the outbound request gets
/// its own, derived from the upstream URI, not copied from the inbound one), and the hop-by-hop
/// set from RFC 7230 §6.1, which describes this connection's leg, not the next one.
fn strip_request_headers(headers: &HeaderMap) -> HeaderMap {
    const HOP_BY_HOP: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
    ];

    headers
        .iter()
        .filter(|(name, _)| {
            let name = name.as_str();
            name != X_PAYMENT && !name.starts_with(X_TOLLGATE_PREFIX) && !HOP_BY_HOP.contains(&name)
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// Joins `upstream_url` and the captured path/query without producing a double slash. Both sides
/// are already known-good: `upstream_url` was SSRF-validated at registration (Task 4.2), and the
/// pinned connector (this module) validates it again at connect time.
fn build_upstream_uri(upstream_url: &str, path: &str, query: Option<&str>) -> Result<Uri, BoxError> {
    let base = upstream_url.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    let mut joined = format!("{base}/{path}");
    if let Some(q) = query {
        joined.push('?');
        joined.push_str(q);
    }
    joined.parse::<Uri>().map_err(|e| e.into())
}

/// Everything about the inbound request `proxy_request` needs, grouped so the function itself
/// takes a provider and one bundle rather than a long parameter list.
pub struct InboundRequest<'a> {
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub method: Method,
    pub headers: HeaderMap,
    pub body: Body,
    pub client_addr: Option<std::net::SocketAddr>,
}

/// Forwards `method`/`path`/`query`/a filtered header set/`body` to `provider`'s upstream, streams
/// the response back without buffering, and applies `provider.timeout_ms`.
///
/// Redirects are not followed: `architecture.md` §10 step 5 says a proxy that follows redirects
/// must re-validate on every hop, and not following at all is the simpler correct choice for this
/// MVP. A 3xx from the upstream is returned to the caller exactly as received.
pub async fn proxy_request(
    client: &ProxyClient,
    provider: &Provider,
    inbound: InboundRequest<'_>,
) -> Result<axum::response::Response, ProxyError> {
    let uri = build_upstream_uri(&provider.upstream_url, inbound.path, inbound.query)
        .map_err(ProxyError::Upstream)?;

    let mut req_headers = strip_request_headers(&inbound.headers);
    if let Some(addr) = inbound.client_addr
        && let Ok(value) = HeaderValue::from_str(&addr.ip().to_string())
    {
        req_headers.insert(HeaderName::from_static("x-forwarded-for"), value);
    }

    let mut builder = http::Request::builder().method(inbound.method).uri(uri);
    *builder.headers_mut().expect("builder has no error yet") = req_headers;
    let request = builder
        .body(inbound.body)
        .map_err(|e| ProxyError::Upstream(e.into()))?;

    let timeout = Duration::from_millis(provider.timeout_ms.max(0) as u64);

    let _timer = StageTimer::start("upstream");
    let response = match tokio::time::timeout(timeout, client.request(request)).await {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => return Err(ProxyError::Upstream(e.into())),
        Err(_elapsed) => return Err(ProxyError::Timeout),
    };

    let (parts, incoming) = response.into_parts();
    let stream = BodyDataStream::new(incoming);
    let body = Body::from_stream(stream);

    let mut out = axum::response::Response::new(body);
    *out.status_mut() = parts.status;
    *out.headers_mut() = parts.headers;

    Ok(out)
}

/// Maps a `ProxyError` to the status code `architecture.md` §4.3 assigns it: a timeout is `504`
/// (the provider's configured `timeout_ms` elapsed), anything else reaching this point is a
/// connector/protocol failure the caller could not have prevented, `502`.
pub fn proxy_error_response(err: ProxyError) -> axum::response::Response {
    use axum::response::IntoResponse;
    use tollgate_core::error::ErrorBody;

    match err {
        ProxyError::Timeout => (
            StatusCode::GATEWAY_TIMEOUT,
            axum::Json(ErrorBody::new("upstream_timeout", "upstream did not respond in time")),
        )
            .into_response(),
        ProxyError::Upstream(e) => (
            StatusCode::BAD_GATEWAY,
            axum::Json(ErrorBody::new("upstream_error", e.to_string())),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod rebinding {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::net::TcpListener;

    /// Accepts exactly one connection and returns the listener's own address, so a test can tell
    /// which of two listeners actually received the dial.
    async fn accept_one(listener: TcpListener) -> SocketAddr {
        let (_socket, _peer) = listener.accept().await.expect("accept should succeed");
        listener.local_addr().expect("listener should have a local addr")
    }

    /// `architecture.md` §10 step 3, tested directly: a resolver that would answer differently on
    /// a second call must never get the chance to, because `dial` only calls it once per attempt
    /// and connects to exactly the `SocketAddr` that one call returned. Modelled with two real
    /// local listeners rather than a real DNS name, since what a hostname resolves to in this
    /// sandbox is not something a test should depend on; the stub resolver stands in for "DNS
    /// answers differently the second time" without needing a real rebinding DNS record.
    #[tokio::test]
    #[ignore = "binds local sockets; run explicitly"]
    async fn dials_first_validated_address_both_times() {
        // Bind once just to allocate two free ports, then release them immediately: each loop
        // iteration below needs to rebind the same addresses fresh.
        let (addr_a, addr_b) = {
            let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
            (
                listener_a.local_addr().unwrap(),
                listener_b.local_addr().unwrap(),
            )
        };

        for attempt in 0..2 {
            let listener_a = TcpListener::bind(addr_a).await.unwrap();
            let listener_b = TcpListener::bind(addr_b).await.unwrap();

            let resolve_calls = Arc::new(AtomicUsize::new(0));
            let calls = resolve_calls.clone();
            // The stub: first call answers with the validated address; a hypothetical second
            // call within the same attempt would answer with the different, "rebound" one. A
            // correctly pinned dial never makes that second call at all.
            let resolver = move |_host: String, _port: u16| {
                let calls = calls.clone();
                async move {
                    let n = calls.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        Ok(vec![addr_a])
                    } else {
                        Ok(vec![addr_b])
                    }
                }
            };

            let uri: Uri = "http://rebind.test.invalid/".parse().unwrap();
            let a_task = tokio::spawn(accept_one(listener_a));
            let b_task = tokio::spawn(async move {
                tokio::time::timeout(std::time::Duration::from_millis(200), accept_one(listener_b)).await
            });

            let dialed = dial(&uri, resolver).await;
            assert!(dialed.is_ok(), "attempt {attempt}: dial should succeed");

            let accepted_on_a = a_task.await.expect("listener a task should not panic");
            assert_eq!(
                accepted_on_a, addr_a,
                "attempt {attempt}: the connection must land on the first (validated) address"
            );

            let b_result = b_task.await.expect("listener b task should not panic");
            assert!(
                b_result.is_err(),
                "attempt {attempt}: the second, different address must never be dialed"
            );

            assert_eq!(
                resolve_calls.load(Ordering::SeqCst),
                1,
                "attempt {attempt}: the resolver must be called exactly once per dial, \
                 never once to validate and again to connect"
            );
        }
    }
}
