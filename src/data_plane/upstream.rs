//! The one place the process connects to the providers' APIs.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST, USER_AGENT};
use http::{HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::Value;
use time::{Duration as StdDuration, OffsetDateTime};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::connect::Connector;
use super::tls::client_config;
use crate::config::DataPlaneSettings;
use crate::pool::{Account, OAuthCredential, Profile, Secret};
use crate::provider::anthropic::{ANTHROPIC_BETA, OAUTH_BETA, PROFILE_PATH};
use crate::provider::{Grant, Provider, codex, jwt_claims};

#[derive(Debug)]
pub enum SendError {
    /// Connection failure, reset, TLS failure or the first-byte deadline.
    Network(String),
    /// Anything else while attempting.
    Other(String),
}

#[derive(Debug)]
pub enum RefreshFailure {
    /// `code` is the provider's reason, when the body names a known one.
    Permanent {
        status: StatusCode,
        code: Option<&'static str>,
    },
    Transient(String),
}

#[derive(Debug)]
pub enum UsageFailure {
    Unauthorized,
    Failed(String),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::Network(m) | SendError::Other(m) => f.write_str(m),
        }
    }
}

/// The failure's description is the whole source chain, not the
/// client's one-word kind.
fn describe(error: &dyn std::error::Error) -> String {
    let mut out = error.to_string();
    let mut source = error.source();
    while let Some(e) = source {
        out.push_str(": ");
        out.push_str(&e.to_string());
        source = e.source();
    }
    out
}

pub struct Upstream {
    client: Client<Connector, Full<Bytes>>,
    /// Stands in for every provider's origins, the token endpoints included.
    override_origin: Option<Uri>,
    slots: Arc<Semaphore>,
    first_byte: Duration,
}

impl Upstream {
    pub fn new(settings: &DataPlaneSettings) -> Result<Self, String> {
        let tls = client_config()?;
        let connector = Connector::new(tls, settings.corporate_proxy_url.as_ref())?;
        let client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(settings.max_connections)
            .build(connector);
        Ok(Self {
            client,
            override_origin: settings.upstream_origin.clone(),
            slots: Arc::new(Semaphore::new(settings.max_connections)),
            first_byte: Duration::from_secs(settings.first_byte_timeout_seconds),
        })
    }

    pub fn override_origin(&self) -> Option<&Uri> {
        self.override_origin.as_ref()
    }

    pub fn override_active(&self) -> bool {
        self.override_origin.is_some()
    }

    pub fn origin(&self, provider: Provider) -> Uri {
        self.override_origin
            .clone()
            .unwrap_or_else(|| Uri::from_static(provider.api_origin()))
    }

    pub fn host_header(&self, provider: Provider) -> HeaderValue {
        HeaderValue::from_str(self.origin(provider).authority().map_or("", |a| a.as_str()))
            .expect("valid authority")
    }

    /// The token endpoint's origin: the loopback override when one is active
    /// for the harness, otherwise the provider's token host.
    fn token_origin(&self, provider: Provider) -> Uri {
        self.override_origin
            .clone()
            .unwrap_or_else(|| Uri::from_static(provider.token_origin()))
    }

    fn token_request(
        &self,
        provider: Provider,
        grant: Grant<'_>,
    ) -> Result<Request<Bytes>, http::Error> {
        let origin = self.token_origin(provider);
        let call = provider.token_request(grant);
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(Self::uri_on(&origin, call.path))
            .header(
                HOST,
                HeaderValue::from_str(origin.authority().map_or("", |a| a.as_str()))
                    .expect("valid authority"),
            )
            .header(CONTENT_TYPE, call.content_type)
            .header(ACCEPT, call.accept);
        if let Some(agent) = call.user_agent {
            request = request.header(USER_AGENT, agent);
        }
        request.body(Bytes::from(call.body))
    }

    pub fn uri_for(&self, provider: Provider, path_and_query: &str) -> Uri {
        Self::uri_on(&self.origin(provider), path_and_query)
    }

    /// The token endpoint lives on its own origin, not the one attempts
    /// use, so the URI and the `host` header must be built from the same place.
    fn uri_on(origin: &Uri, path_and_query: &str) -> Uri {
        Uri::builder()
            .scheme(origin.scheme().cloned().expect("origin has a scheme"))
            .authority(
                origin
                    .authority()
                    .cloned()
                    .expect("origin has an authority"),
            )
            .path_and_query(path_and_query)
            .build()
            .expect("origin plus a valid path")
    }

    /// One attempt under the first-byte deadline the caller's configuration
    /// snapshot names. The permit bounds live connections
    /// and travels with the body.
    pub async fn send(
        &self,
        request: Request<Bytes>,
        first_byte: Duration,
    ) -> Result<(Response<Incoming>, OwnedSemaphorePermit), SendError> {
        let permit = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .map_err(|_| SendError::Other("upstream closed".into()))?;
        let request = request.map(Full::new);
        let response = tokio::time::timeout(first_byte, self.client.request(request))
            .await
            .map_err(|_| {
                SendError::Network("no response headers before the first-byte deadline".into())
            })?
            .map_err(|e| {
                if e.is_connect() || source_is_transport(&e) {
                    SendError::Network(describe(&e))
                } else {
                    SendError::Other(describe(&e))
                }
            })?;
        Ok((response, permit))
    }

    /// Exchange an authorisation code for the token family and the identity
    /// it speaks for. The failure text names classes only — a response body is
    /// never returned, logged or persisted.
    pub async fn exchange_code(
        &self,
        provider: Provider,
        grant: Grant<'_>,
    ) -> Result<(OAuthCredential, Profile), String> {
        let request = self
            .token_request(provider, grant)
            .map_err(|e| e.to_string())?;
        let (response, _permit) = self
            .send(request, self.first_byte)
            .await
            .map_err(|e| format!("the code exchange failed: {e}"))?;
        let status = response.status();
        let body = tokio::time::timeout(self.first_byte, response.into_body().collect())
            .await
            .map_err(|_| "the code exchange body timed out".to_string())?
            .map_err(|e| e.to_string())?
            .to_bytes();
        if !status.is_success() {
            // The status alone; the response body is never surfaced.
            return Err(format!("the token endpoint answered {status}"));
        }
        let value: Value = serde_json::from_slice(&body)
            .map_err(|e| format!("token response is not JSON: {e}"))?;
        let credential = tokens_to_credential(&value)?;
        let profile = match provider {
            Provider::Anthropic => match self.fetch_profile(credential.access_token.expose()).await
            {
                Ok(profile) if profile.account_uuid.is_some() => profile,
                Ok(_) => {
                    return Err(
                        "the profile carries no account UUID; the account was not saved".into(),
                    );
                }
                Err(reason) => return Err(format!("profile lookup failed: {reason}")),
            },
            Provider::Codex => codex::profile(&value)?,
        };
        Ok((credential, profile))
    }

    /// Exchange a refresh token for a replacement family.
    pub async fn refresh_family(
        &self,
        provider: Provider,
        refresh_token: &Secret,
        deadline: Duration,
    ) -> Result<OAuthCredential, RefreshFailure> {
        let grant = Grant::Refresh {
            refresh_token: refresh_token.expose(),
        };
        let request = self
            .token_request(provider, grant)
            .map_err(|error| RefreshFailure::Transient(error.to_string()))?;
        tokio::time::timeout(deadline, async {
            let (response, _permit) = self
                .send(request, self.first_byte)
                .await
                .map_err(|error| RefreshFailure::Transient(error.to_string()))?;
            let status = response.status();
            let body = response
                .into_body()
                .collect()
                .await
                .map_err(|error| RefreshFailure::Transient(error.to_string()))?
                .to_bytes();
            if !status.is_success() {
                return Err(refresh_failure(
                    status,
                    provider.refresh_failure_code(&body),
                ));
            }
            let value: Value = serde_json::from_slice(&body).map_err(|error| {
                RefreshFailure::Transient(format!("token response is not JSON: {error}"))
            })?;
            tokens_to_credential(&value).map_err(RefreshFailure::Transient)
        })
        .await
        .map_err(|_| RefreshFailure::Transient("token refresh deadline elapsed".into()))?
    }

    /// The identity behind a bearer, through the same origin as attempts.
    pub async fn fetch_profile(&self, access_token: &str) -> Result<Profile, String> {
        let request = Request::builder()
            .method(Method::GET)
            .uri(self.uri_for(Provider::Anthropic, PROFILE_PATH))
            .header(HOST, self.host_header(Provider::Anthropic))
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .header(ANTHROPIC_BETA, OAUTH_BETA)
            .header(ACCEPT, "application/json")
            .body(Bytes::new())
            .map_err(|e| e.to_string())?;
        let (response, _permit) = self
            .send(request, self.first_byte)
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status();
        let body = tokio::time::timeout(self.first_byte, response.into_body().collect())
            .await
            .map_err(|_| "profile body timed out".to_string())?
            .map_err(|e| e.to_string())?
            .to_bytes();
        if !status.is_success() {
            return Err(format!("profile lookup answered {status}"));
        }
        let value: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| format!("profile is not JSON: {e}"))?;
        let text = |v: &serde_json::Value| v.as_str().map(String::from);
        let uuid = |v: &serde_json::Value| v.as_str().and_then(|s| s.parse().ok());
        Ok(Profile {
            email: text(&value["account"]["email"]),
            account_uuid: uuid(&value["account"]["uuid"]),
            organization_uuid: uuid(&value["organization"]["uuid"]),
            organization_name: text(&value["organization"]["name"]),
            chatgpt_account_id: None,
        })
    }

    /// One zero-spend usage read through the shared upstream
    /// client. The caller owns the per-account deadline and the one 401 retry.
    pub async fn fetch_usage(&self, account: &Account) -> Result<Value, UsageFailure> {
        let provider = account.provider;
        let mut request = Request::builder()
            .method(Method::GET)
            .uri(self.uri_for(provider, provider.usage_path()))
            .header(HOST, self.host_header(provider))
            .header(ACCEPT, "application/json")
            .body(Bytes::new())
            .map_err(|error| UsageFailure::Failed(error.to_string()))?;
        provider.inject_credential(request.headers_mut(), account);
        let (response, _permit) = self
            .send(request, self.first_byte)
            .await
            .map_err(|error| UsageFailure::Failed(error.to_string()))?;
        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(UsageFailure::Unauthorized);
        }
        if !response.status().is_success() {
            return Err(UsageFailure::Failed(format!(
                "usage endpoint answered {}",
                response.status()
            )));
        }
        let body = http_body_util::Limited::new(response.into_body(), 1024 * 1024)
            .collect()
            .await
            .map_err(|error| UsageFailure::Failed(error.to_string()))?
            .to_bytes();
        serde_json::from_slice(&body)
            .map_err(|error| UsageFailure::Failed(format!("usage response is not JSON: {error}")))
    }
}

fn refresh_failure(status: StatusCode, code: Option<&'static str>) -> RefreshFailure {
    if matches!(
        status,
        StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) {
        RefreshFailure::Permanent { status, code }
    } else {
        RefreshFailure::Transient(format!("token endpoint answered {status}"))
    }
}

/// `access_token`, `refresh_token`, and `expires_in` (seconds), `expires_at`
/// (unix seconds) or the access token's own JWT `exp`; a missing
/// `refresh_token` keeps the old one when a caller refreshes — here it means
/// the family has none.
fn tokens_to_credential(value: &Value) -> Result<OAuthCredential, String> {
    let access_token = value["access_token"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or("the token response carries no access_token")?;
    let now = OffsetDateTime::now_utc();
    let expires_at = if let Some(seconds) = value["expires_in"].as_i64() {
        now + StdDuration::seconds(seconds)
    } else if let Some(at) = value["expires_at"]
        .as_i64()
        .or_else(|| jwt_claims(access_token)?["exp"].as_i64())
    {
        OffsetDateTime::from_unix_timestamp(at)
            .map_err(|_| "the token response carries an impossible expiry".to_string())?
    } else {
        return Err("the token response carries no expiry".into());
    };
    Ok(OAuthCredential {
        access_token: Secret::new(access_token.to_string()),
        refresh_token: value["refresh_token"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| Secret::new(s.to_string())),
        expires_at,
        last_refresh_attempt_at: None,
        last_refresh_success_at: None,
        refresh_not_before: None,
    })
}

/// Closed connections, resets and TLS failures surface as I/O sources on the hyper error.
fn source_is_transport(error: &hyper_util::client::legacy::Error) -> bool {
    let mut source = std::error::Error::source(error);
    while let Some(source_error) = source {
        if source_error.is::<std::io::Error>()
            || source_error
                .downcast_ref::<hyper::Error>()
                .is_some_and(|error| {
                    error.is_incomplete_message() || error.is_closed() || error.is_canceled()
                })
        {
            return true;
        }
        source = source_error.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tokio::net::TcpListener;

    use super::*;

    fn upstream_at(addr: std::net::SocketAddr) -> Upstream {
        let document = format!("version = 1\n[data_plane]\nupstream_origin = \"http://{addr}\"\n");
        let config =
            crate::config::parse(document.as_bytes(), Path::new(".")).expect("test configuration");
        Upstream::new(&config.data_plane).expect("test upstream")
    }

    /// An override makes every origin one, so the case that matters has none.
    #[test]
    fn token_calls_go_to_the_provider_s_token_origin_not_its_attempt_origin() {
        let config =
            crate::config::parse(b"version = 1\n", Path::new(".")).expect("test configuration");
        let upstream = Upstream::new(&config.data_plane).expect("test upstream");
        for (provider, host, path) in [
            (
                Provider::Anthropic,
                "platform.claude.com",
                "/v1/oauth/token",
            ),
            (Provider::Codex, "auth.openai.com", "/oauth/token"),
        ] {
            let request = upstream
                .token_request(provider, Grant::Refresh { refresh_token: "r" })
                .expect("request builds");

            assert_eq!(request.uri().authority().map(|a| a.as_str()), Some(host));
            assert_eq!(request.headers()[HOST], host);
            assert_eq!(request.uri().path(), path);
            assert_ne!(
                request.uri().authority(),
                upstream.origin(provider).authority()
            );
        }
    }

    #[test]
    fn an_override_puts_every_token_endpoint_on_the_overridden_origin() {
        let upstream = upstream_at("127.0.0.1:9999".parse().expect("valid address"));
        for provider in Provider::ALL {
            let request = upstream
                .token_request(provider, Grant::Refresh { refresh_token: "r" })
                .expect("request builds");

            assert_eq!(
                request.uri().authority().map(|a| a.as_str()),
                Some("127.0.0.1:9999")
            );
        }
    }

    #[test]
    fn a_token_response_without_an_expiry_uses_the_access_token_s_exp() {
        let access = codex::fixture_jwt(serde_json::json!({ "exp": 4_070_908_800_i64 }));
        let family = tokens_to_credential(&serde_json::json!({ "access_token": access }))
            .expect("credential");
        assert_eq!(family.expires_at.unix_timestamp(), 4_070_908_800);

        assert!(tokens_to_credential(&serde_json::json!({ "access_token": "opaque" })).is_err());
    }

    #[test]
    fn refresh_statuses_have_their_protocol_failure_classes() {
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
        ] {
            assert!(matches!(
                refresh_failure(status, Some("refresh_token_reused")),
                RefreshFailure::Permanent { status: found, code: Some("refresh_token_reused") }
                    if found == status
            ));
        }
        for code in 500..=599 {
            assert!(matches!(
                refresh_failure(StatusCode::from_u16(code).expect("5xx status"), None),
                RefreshFailure::Transient(_)
            ));
        }
    }

    #[tokio::test]
    async fn refresh_deadline_bounds_a_stalling_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stall");
        let upstream = upstream_at(listener.local_addr().expect("stall address"));
        let stall = tokio::spawn(async move {
            let (_connection, _) = listener.accept().await.expect("accept refresh");
            std::future::pending::<()>().await;
        });
        let started = tokio::time::Instant::now();

        let result = upstream
            .refresh_family(
                Provider::Anthropic,
                &Secret::new("fixture-refresh".into()),
                Duration::from_secs(1),
            )
            .await;

        stall.abort();
        assert!(matches!(result, Err(RefreshFailure::Transient(_))));
        assert!(started.elapsed() >= Duration::from_secs(1));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn refresh_connection_failure_is_transient() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind closed");
        let addr = listener.local_addr().expect("closed address");
        drop(listener);

        let result = upstream_at(addr)
            .refresh_family(
                Provider::Anthropic,
                &Secret::new("fixture-refresh".into()),
                Duration::from_secs(1),
            )
            .await;

        assert!(matches!(result, Err(RefreshFailure::Transient(_))));
    }
}
