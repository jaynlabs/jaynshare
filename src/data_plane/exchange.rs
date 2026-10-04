//! One exchange: read the request, choose the one candidate account, make its
//! attempts, relay the answer, leave one audit record. An exchange always has
//! exactly one candidate.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, HOST, RETRY_AFTER};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Either, Full, Limited};
use hyper::body::Incoming;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::audit::{ErrorClass, Mode, Principal, Record, ServingAccount};
use crate::capture::ExchangeCapture;
use crate::config::{Config, TelemetryPolicy};
use crate::pool::quota;
use crate::pool::ramp::Admit;
use crate::pool::refresh::{self, Outcome, Trigger};
use crate::pool::selection::{self, Cause, NoService, RequestFacts};
use crate::pool::{Resolve, SessionKey};
use crate::provider::Provider;
use crate::provider::anthropic::error_type;
use crate::server::Server;

use super::attempt;
use super::egress;
use super::envelope::{self, json_response};
use super::intent::{self, Intent};
use super::relay::{self, BodyEnd, RelayBody, ResponseBody, strip_response_headers};
use tokio::sync::OwnedSemaphorePermit;

use super::upstream::SendError;
use super::usage::UsageExtractor;

/// Never forwarded above this; Anthropic refuses larger bodies anyway.
pub(super) const BODY_LIMIT: usize = 32 * 1024 * 1024;
/// The one inline wait before a synthetic 429.
const INLINE_WAIT_MAX: u64 = 15;
/// Hold poll interval bound.
const HOLD_POLL_MAX: u64 = 60;
/// `retry-after` when nothing gives a time.
const RETRY_AFTER_DEFAULT: u64 = 60;
/// The clamp for any wait the proxy performs itself.
const THROTTLE_CLAMP_MAX: u64 = 300;
/// `retry-after` when the pinned account is unavailable.
const PINNED_RETRY_AFTER: u64 = 5;

/// The client connection is closed without a response.
#[derive(Debug)]
pub struct CloseConnection;

impl std::fmt::Display for CloseConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("closing the client connection without a response")
    }
}

impl std::error::Error for CloseConnection {}

/// The audit record under construction; written exactly once, on every path.
struct Exchange {
    server: Arc<Server>,
    /// Whose envelope the proxy's own answers take.
    provider: Provider,
    started: Instant,
    record: Record,
    /// The session this exchange counts against, once begun.
    session: Option<SessionKey>,
    /// The account of the last attempt, for the session's `last_served`.
    last_attempted: Option<Uuid>,
    /// The exchange's one inline wait, spent by a hold or a
    /// refresh-wait, whichever comes first.
    inline_wait_used: bool,
    written: bool,
}

impl Exchange {
    fn set_serving(&mut self, handle: Uuid, cause: Cause) {
        let pool = self.server.pool.lock().expect("pool lock");
        if let Some(a) = pool.get(handle) {
            self.record.serving_account = Some(ServingAccount {
                display_name: a.display_name.clone(),
                account_uuid: a.profile.account_uuid,
                organization_uuid: a.profile.organization_uuid,
            });
        }
        self.record.selection_cause = Some(cause);
        self.record.no_service_reason = None;
    }

    fn display_name(&self, handle: Uuid) -> String {
        let pool = self.server.pool.lock().expect("pool lock");
        pool.get(handle)
            .map_or_else(|| handle.to_string(), |a| a.display_name.clone())
    }

    fn write(&mut self, status: Option<u16>, error_class: Option<ErrorClass>) {
        if self.written {
            return;
        }
        self.written = true;
        self.record.status = status;
        self.record.error_class = error_class;
        self.record.duration_ms = self.started.elapsed().as_millis() as u64;
        if let Some(key) = self.session.take() {
            self.server.pool.lock().expect("pool lock").session_end(
                &key,
                self.last_attempted,
                OffsetDateTime::now_utc(),
            );
        }
        self.server.record_exchange(&self.record);
    }

    fn respond(
        &mut self,
        response: Response<ResponseBody>,
        error_class: Option<ErrorClass>,
    ) -> Response<ResponseBody> {
        self.write(Some(response.status().as_u16()), error_class);
        response
    }

    /// A `proxy_error` with the given status.
    fn proxy_error(
        &mut self,
        status: StatusCode,
        message: String,
        error_class: ErrorClass,
    ) -> Response<ResponseBody> {
        self.respond(
            envelope::error(self.provider, status, error_type::PROXY, &message),
            Some(error_class),
        )
    }
}

impl Drop for Exchange {
    fn drop(&mut self) {
        // A client that leaves while held still leaves one record.
        self.write(None, None);
    }
}

/// How an exchange entered: base-URL mode reads the caller's
/// own headers, an intercepted tunnel brings the principal and intent it
/// fixed at `CONNECT`; `mode` is what its audit record carries.
pub struct Entry {
    pub principal: Principal,
    pub mode: Mode,
    /// Whose API the request speaks: the base-URL listener's is Anthropic's,
    /// a tunnel's is its intercepted host's.
    pub provider: Provider,
    /// `Ok(None)` reads the request's own headers, `Ok(Some)` is the
    /// tunnel's fixed intent, `Err` is a malformed user field — every request
    /// inside that tunnel is a 400.
    pub intent: Result<Option<Intent>, String>,
}

impl Entry {
    /// The base-URL listener: the principal it resolved, nothing fixed.
    pub fn base_url(principal: Principal) -> Entry {
        Entry {
            principal,
            mode: Mode::BaseUrl,
            provider: Provider::Anthropic,
            intent: Ok(None),
        }
    }
}

/// An unauthenticated `401` is the one exchange with no principal, and
/// the operator traces it through its audit record — a stolen secret is
/// indistinguishable from a wrong one in every field but the address.
/// The pipeline below never runs for it, nothing being read or selected, so
/// the record is written here with nulls for what did not happen.
pub fn unauthenticated(
    server: &Server,
    peer: SocketAddr,
    request: &Request<Incoming>,
    mode: Mode,
    provider: Option<Provider>,
) -> Response<ResponseBody> {
    server.record_exchange(&Record {
        timestamp: OffsetDateTime::now_utc(),
        duration_ms: 0,
        principal: None,
        source_address: peer.to_string(),
        session_id: provider
            .and_then(|p| request.headers().get(p.session_header()))
            .and_then(|v| v.to_str().ok())
            .map(String::from),
        method: request.method().to_string(),
        path: request.uri().path().to_string(),
        model: None,
        serving_account: None,
        no_service_reason: None,
        selection_cause: None,
        status: Some(StatusCode::UNAUTHORIZED.as_u16()),
        attempts: 0,
        failed_over: false,
        error_class: Some(ErrorClass::Authentication),
        pinned: false,
        mode,
        blocked_pattern: None,
    });
    envelope::unauthenticated()
}

pub async fn run(
    server: Arc<Server>,
    entry: Entry,
    peer: SocketAddr,
    request: Request<Incoming>,
) -> Result<Response<ResponseBody>, CloseConnection> {
    let Entry {
        principal,
        mode,
        provider,
        intent: fixed_intent,
    } = entry;
    // The configuration in force when the exchange begins is the one
    // it keeps; a reload applies to the next exchange.
    let loaded = server.config();
    let settings = &loaded.config;
    let (parts, body) = request.into_parts();
    let path = parts.uri.path().to_string();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_string();
    let session_id = parts
        .headers
        .get(provider.session_header())
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let principal_key = principal.key();
    let mut exchange = Exchange {
        server: Arc::clone(&server),
        provider,
        started: Instant::now(),
        record: Record {
            timestamp: OffsetDateTime::now_utc(),
            duration_ms: 0,
            principal: Some(principal),
            source_address: peer.to_string(),
            session_id: session_id.clone(),
            method: parts.method.to_string(),
            path: path.clone(),
            model: None,
            serving_account: None,
            no_service_reason: None,
            selection_cause: None,
            status: None,
            attempts: 0,
            failed_over: false,
            error_class: None,
            pinned: false,
            mode,
            blocked_pattern: None,
        },
        session: None,
        last_attempted: None,
        inline_wait_used: false,
        written: false,
    };

    // The whole body, bounded, before any attempt.
    let too_large = parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse::<usize>().ok())
        .is_some_and(|n| n > BODY_LIMIT);
    let body = if too_large {
        None
    } else {
        Limited::new(body, BODY_LIMIT)
            .collect()
            .await
            .ok()
            .map(|c| c.to_bytes())
    };
    let Some(body) = body else {
        return Ok(exchange.respond(
            envelope::error(
                provider,
                StatusCode::PAYLOAD_TOO_LARGE,
                error_type::REQUEST_TOO_LARGE,
                "request body exceeds 32 MiB and was not forwarded",
            ),
            Some(ErrorClass::Request),
        ));
    };
    let body_facts = attempt::body_facts(&parts.headers, &body);
    exchange.record.model = body_facts.model.clone();

    // Telemetry under `block` and the provider's local answers are
    // answered here, never forwarded.
    if provider.is_telemetry(&path)
        && settings.data_plane.telemetry_policy == TelemetryPolicy::Block
    {
        return Ok(exchange.respond(json_response(StatusCode::OK, &serde_json::json!({})), None));
    }
    if let Some(answer) = provider.local_answer(&path, &parts.headers) {
        return Ok(exchange.respond(json_response(StatusCode::OK, &answer), None));
    }
    // An account-bound path is refused before any selection,
    // so no pooled credential answers for it and no family 401 errors an
    // account.
    if provider.is_account_bound(&path) {
        return Ok(exchange.proxy_error(
            StatusCode::FORBIDDEN,
            format!(
                "{path} is account-bound: account features (settings, organisations, plugins, skills, MCP servers) are not served through the pool"
            ),
            ErrorClass::Request,
        ));
    }
    let base_facts = RequestFacts {
        provider,
        model: body_facts.model.as_deref(),
        advisor_model: body_facts.advisor_model.as_deref(),
        ..RequestFacts::default()
    };
    // A blocked model ends the exchange before any candidate is consumed.
    if let Some(pattern) = selection::blocked_by(&settings.selection, &base_facts) {
        exchange.record.blocked_pattern = Some(pattern.to_string());
        let model = body_facts
            .model
            .as_deref()
            .or(body_facts.advisor_model.as_deref())
            .unwrap_or("");
        return Ok(exchange.respond(
            envelope::error(
                provider,
                StatusCode::BAD_REQUEST,
                error_type::INVALID_REQUEST,
                &format!("model {model} is blocked by the operator pattern {pattern}"),
            ),
            Some(ErrorClass::Request),
        ));
    }

    // The account-intent token, resolved before any
    // attempt. Inside a tunnel the intent came from the proxy credential's
    // user field and the header was stripped unread.
    let parsed = match fixed_intent {
        Ok(Some(intent)) => Ok(Some(intent)),
        Ok(None) => intent::parse(&parts.headers),
        Err(message) => Err(message),
    };
    let intent = match parsed {
        Ok(intent) => intent,
        Err(message) => {
            return Ok(exchange.respond(
                envelope::error(
                    provider,
                    StatusCode::BAD_REQUEST,
                    error_type::INVALID_REQUEST,
                    &message,
                ),
                Some(ErrorClass::Request),
            ));
        }
    };
    let (pin, preference) = match &intent {
        None => (None, None),
        Some(intent) => {
            // Another provider's account is no match: a 404.
            let resolved = {
                let pool = server.pool.lock().expect("pool lock");
                pool.resolve_in(provider, intent.reference())
                    .map(|a| a.handle)
            };
            let what = if intent.is_pin() { "pin" } else { "preference" };
            match resolved {
                Ok(handle) if intent.is_pin() => {
                    exchange.record.pinned = true;
                    (Some(handle), None)
                }
                Ok(handle) => (None, Some(handle)),
                Err(Resolve::NotFound) => {
                    return Ok(exchange.respond(
                        envelope::error(
                            provider,
                            StatusCode::NOT_FOUND,
                            error_type::NOT_FOUND,
                            &format!("no account matches the {what} {:?}", intent.reference()),
                        ),
                        Some(ErrorClass::Request),
                    ));
                }
                Err(Resolve::Ambiguous(names)) => {
                    return Ok(exchange.respond(
                        envelope::error(
                            provider,
                            StatusCode::BAD_REQUEST,
                            error_type::INVALID_REQUEST,
                            &format!(
                                "the {what} {:?} matches more than one account: {}; qualify it with the organisation name or UUID",
                                intent.reference(),
                                Resolve::listed(&names)
                            ),
                        ),
                        Some(ErrorClass::Request),
                    ));
                }
            }
        }
    };

    // The session this exchange belongs to, if the header names one.
    let session = session_id.map(|id| SessionKey {
        principal: principal_key,
        session_id: id,
    });
    if let Some(key) = &session {
        server
            .pool
            .lock()
            .expect("pool lock")
            .session_begin(key.clone(), OffsetDateTime::now_utc());
        exchange.session = Some(key.clone());
    }

    let mut capture = server
        .capture
        .as_ref()
        .and_then(|c| c.begin(Uuid::new_v4()).ok());
    if let Some(c) = &mut capture {
        c.request(
            &parts.method,
            &parts.uri,
            parts.version,
            &parts.headers,
            &body,
        );
    }

    // The egress guard holds the exchange — connection open, the
    // check URL re-polled — until the pinned address is back, then 503s.
    if let Err(held) = egress::gate(&server, &settings.data_plane.egress).await {
        tracing::warn!(event = "egress_refused", observed = %held.observed, "hold budget spent on the wrong public address; refusing");
        let mut response = exchange.proxy_error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("{held}; check the VPN or the outbound route"),
            ErrorClass::Upstream,
        );
        response
            .headers_mut()
            .insert(RETRY_AFTER, egress::HOLD_RETRY_AFTER.into());
        return Ok(response);
    }

    let mut headers = parts.headers;
    attempt::strip_request_headers(&mut headers);
    headers.insert(HOST, server.upstream.host_header(provider));
    let uri = server.upstream.uri_for(provider, &path_and_query);

    // A failure that is neither a network failure nor a status is the one
    // path that may try another account, and only for an exchange that is
    // neither pinned nor a session's: a session's first attempt is its
    // binding, so its exchange has one candidate. The exclusion set exists
    // for the sessionless case.
    let one_candidate = pin.is_some() || session.is_some();
    let mut exclusion: Vec<Uuid> = Vec::new();
    let mut first_account: Option<Uuid> = None;
    let mut other_failure: Option<String> = None;

    loop {
        let facts = RequestFacts {
            exclusion: &exclusion,
            pin,
            preference,
            ..base_facts.clone()
        };
        let choice = match select_or_wait(
            &server,
            settings,
            &facts,
            session.as_ref(),
            &mut exchange.inline_wait_used,
        )
        .await
        {
            Ok(choice) => choice,
            Err(nobody) => {
                exchange.record.no_service_reason = Some(reason_name(&nobody.reason));
                // The refusal names the rule that produced it —
                // the pin, or the session's binding.
                if nobody.named.is_some() {
                    exchange.record.selection_cause = Some(if pin.is_some() {
                        Cause::Pin
                    } else {
                        Cause::Session
                    });
                }
                if let Some(message) = other_failure {
                    // Every account the attempt could use failed the same way.
                    return Ok(exchange.proxy_error(
                        StatusCode::BAD_GATEWAY,
                        format!("every attempt failed: {message}"),
                        ErrorClass::Upstream,
                    ));
                }
                return Ok(refuse_nobody(&mut exchange, nobody));
            }
        };
        let handle = choice.handle;
        if let (Some(from), Some(cause)) = (choice.default_moved_from, choice.default_moved_cause) {
            tracing::info!(event = "default_moved", from = %from, to = %handle, cause = %cause, "default account moved");
        }
        if choice.binds {
            tracing::debug!(event = "session_bound", account = %handle, "session bound at its first attempt");
        }
        if choice.advisor_fallback
            && let Some(advisor) = body_facts.advisor_model.as_deref()
        {
            server.log_advisor_fallback(advisor);
        }
        first_account.get_or_insert(handle);
        exchange.set_serving(handle, choice.cause);
        exchange.record.failed_over = first_account != Some(handle);

        match refresh::ensure_fresh(&server, handle, Trigger::Proactive).await {
            Outcome::Ready => {}
            Outcome::Errored => return Ok(refuse_errored_credential(&mut exchange, handle)),
            Outcome::Wait { until } => {
                let display_name = exchange.display_name(handle);
                match settle_refresh_wait(
                    &server,
                    handle,
                    &display_name,
                    until,
                    Trigger::Proactive,
                    &mut exchange.inline_wait_used,
                )
                .await
                {
                    Outcome::Ready => {}
                    Outcome::Errored => {
                        return Ok(refuse_errored_credential(&mut exchange, handle));
                    }
                    Outcome::Wait { until } => {
                        return Ok(refuse_refresh_wait(&mut exchange, handle, until));
                    }
                }
            }
        }

        // The headers stay credential-free here: `attempt_candidate` injects
        // the pool's newest credential itself, so the retry after a forced
        // refresh carries the rotated token.
        let (attempt_headers, attempt_body, display_name, kind) = {
            let pool = server.pool.lock().expect("pool lock");
            let Some(account) = pool.get(handle) else {
                exclusion.push(handle);
                continue;
            };
            let mut h = headers.clone();
            let rewritten = provider.rewrite_body(body.clone(), &path, account);
            if !rewritten.is_empty() || headers.contains_key(CONTENT_LENGTH) {
                attempt::set_content_length(&mut h, rewritten.len());
            }
            (h, rewritten, account.display_name.clone(), account.kind())
        };
        exchange.last_attempted = Some(handle);

        let attempt = attempt_candidate(AttemptInput {
            server: &server,
            provider,
            capture: capture.as_mut(),
            handle,
            display_name: &display_name,
            method: &parts.method,
            uri: &uri,
            headers: attempt_headers,
            body: attempt_body,
            model: body_facts.model.as_deref(),
            settings,
            attempts: &mut exchange.record.attempts,
            inline_wait_used: &mut exchange.inline_wait_used,
        })
        .await;

        let (mut response_parts, incoming, permit, collected) = match attempt {
            Attempt::Served {
                response,
                permit,
                revalidated,
            } => {
                let status = response.status();
                // Response headers teach the serving account before
                // anything is relayed. A 429 was already processed above
                // (its own observations stay unchanged).
                {
                    let mut pool = server.pool.lock().expect("pool lock");
                    pool.count_request(handle);
                    let applied = pool.observe_response_headers(
                        handle,
                        body_facts.model.as_deref(),
                        response.headers(),
                        OffsetDateTime::now_utc(),
                    );
                    // A revalidation's non-429 returns the account
                    // to ordinary consideration — usable quota fields are applied
                    // (capacity clears exhaustion holds on their own), a response
                    // with none leaves the buckets unknown, and the admission hold
                    // clears at once in both cases.
                    if choice.cause == Cause::Revalidation || revalidated {
                        let (ramp, now) = (&settings.selection.ramp, OffsetDateTime::now_utc());
                        if applied {
                            pool.clear_throttle_hold(handle, ramp, now);
                        } else {
                            pool.clear_holds_after_revalidation(handle, ramp, now);
                        }
                        server.mark_quota_dirty();
                    } else if applied {
                        server.mark_quota_dirty();
                    }
                }
                // The 403 arm — the exchange ends with the 502; the
                // account is not errored.
                if status == StatusCode::FORBIDDEN {
                    tracing::warn!(event = "account_refused_403", account = %display_name, "403 upstream; ending the exchange");
                    return Ok(exchange.proxy_error(
                        StatusCode::BAD_GATEWAY,
                        format!(
                            "{} answered 403 for {display_name}; check the server's egress address",
                            provider.upstream_name()
                        ),
                        ErrorClass::Upstream,
                    ));
                }
                let (parts, incoming) = response.into_parts();
                (parts, Either::Left(incoming), permit, None)
            }
            Attempt::Classified429 {
                parts,
                collected,
                permit,
            } => (
                parts,
                Either::Right(Full::new(collected.clone().unwrap_or_default())),
                permit,
                collected,
            ),
            Attempt::Network(message) => {
                tracing::warn!(event = "upstream_network_failure", account = %display_name, error = %message, "second failure; closing the client connection");
                exchange.write(None, Some(ErrorClass::Upstream));
                return Err(CloseConnection);
            }
            Attempt::Other(message) => {
                tracing::warn!(event = "upstream_attempt_failed", account = %display_name, error = %message, "attempt failed");
                if one_candidate {
                    return Ok(exchange.proxy_error(
                        StatusCode::BAD_GATEWAY,
                        format!("the attempt on {display_name} failed: {message}"),
                        ErrorClass::Upstream,
                    ));
                }
                other_failure = Some(message);
                exclusion.push(handle);
                continue;
            }
            Attempt::Refused401 {
                after_refresh,
                errored_by_refresh,
            } => {
                // A 401 that survived the exchange's one forced
                // refresh — or any 401 on an API key — errors the account and
                // ends the exchange with the proxy's own 502. The engine's
                // safe reason is already persisted when it errored the
                // account itself.
                tracing::warn!(event = "account_refused_401", account = %display_name, after_refresh, "credential refused; ending the exchange");
                if !errored_by_refresh {
                    let reason = match kind {
                        crate::pool::Kind::ApiKey => {
                            "upstream 401 on api_key credential".to_string()
                        }
                        crate::pool::Kind::OAuth if after_refresh => {
                            "upstream 401 on oauth credential after a forced refresh".to_string()
                        }
                        crate::pool::Kind::OAuth => "upstream 401 on oauth credential".to_string(),
                    };
                    let now = OffsetDateTime::now_utc();
                    if let Err(e) = server.mutate_pool(|pool| {
                        pool.mark_errored(handle, reason, now);
                        Ok::<(), ()>(())
                    }) {
                        tracing::error!(event = "state_write_failed", error = ?e, "could not persist errored state");
                    }
                }
                return Ok(exchange.proxy_error(
                    StatusCode::BAD_GATEWAY,
                    format!(
                        "{} refused the credential of {display_name}; the operator must re-add the account",
                        provider.upstream_name()
                    ),
                    ErrorClass::Authentication,
                ));
            }
            Attempt::RefreshWait { until } => {
                return Ok(refuse_refresh_wait(&mut exchange, handle, until));
            }
        };

        // Relayed as is; a 429 reaches the client classified and
        // byte-identical.
        strip_response_headers(&mut response_parts.headers);
        let status = response_parts.status;
        if let Some(c) = &mut capture {
            c.response(status, &response_parts.headers);
        }
        let content_type = response_parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());
        let usage = UsageExtractor::for_content_type(content_type);
        let idle = Duration::from_secs(settings.data_plane.body_idle_timeout_seconds);
        exchange.record.status = Some(status.as_u16());
        let error_class = match status.as_u16() {
            429 => Some(ErrorClass::RateLimit),
            s if s >= 500 => Some(ErrorClass::Upstream),
            _ => None,
        };
        let server_for_end = Arc::clone(&server);
        let mut exchange_at_end = exchange;
        let on_end = Box::new(move |end: BodyEnd| {
            let (tokens, class) = match end {
                BodyEnd::Complete(t) | BodyEnd::Dropped(t) => (t, error_class),
                BodyEnd::Failed(t) => (t, Some(ErrorClass::Upstream)),
            };
            if tokens.input > 0 || tokens.output > 0 {
                // Usage totals are runtime facts; the
                // traffic counters alone never schedule a quota-state write.
                server_for_end.pool.lock().expect("pool lock").add_usage(
                    handle,
                    tokens.input,
                    tokens.output,
                );
            }
            exchange_at_end.write(Some(status.as_u16()), class);
            drop(permit);
        });
        let body = match collected {
            // A classified 429 the proxy already read: relayed as one frame.
            Some(bytes) => {
                let tokens = {
                    let mut usage = UsageExtractor::for_content_type(content_type);
                    usage.feed(&bytes);
                    usage.finish()
                };
                relay::FullBody::new(bytes, tokens, on_end).boxed()
            }
            None => {
                let Either::Left(incoming) = incoming else {
                    unreachable!("an unclassified body streams, it is not pre-read")
                };
                RelayBody::new(incoming, idle, usage, capture, on_end).boxed()
            }
        };
        return Ok(Response::from_parts(response_parts, body));
    }
}

fn build_request(method: &Method, uri: &Uri, headers: &HeaderMap, body: Bytes) -> Request<Bytes> {
    let mut request = Request::builder()
        .method(method.clone())
        .uri(uri.clone())
        .body(body)
        .expect("method and uri are valid");
    *request.headers_mut() = headers.clone();
    request
}

/// Everything one candidate's attempt loop needs from the exchange.
struct AttemptInput<'a> {
    server: &'a Arc<Server>,
    provider: Provider,
    capture: Option<&'a mut ExchangeCapture>,
    handle: Uuid,
    display_name: &'a str,
    method: &'a Method,
    uri: &'a Uri,
    /// The credential-free request headers (HOST and `content-length` set);
    /// the attempt loop injects the pool's newest credential every attempt.
    headers: HeaderMap,
    body: Bytes,
    model: Option<&'a str>,
    /// The exchange's configuration snapshot.
    settings: &'a Config,
    /// Bumped once per network attempt, for capture and the audit record.
    attempts: &'a mut u32,
    /// The exchange's one inline wait, shared with the hold
    /// wait; a refresh-wait the exchange already waited for must refuse.
    inline_wait_used: &'a mut bool,
}

/// What the exchange does with one candidate's outcome.
enum Attempt {
    /// A non-429 answer, relayed as it streams. `revalidated` says admission
    /// released this attempt as the revalidation request.
    Served {
        response: Response<Incoming>,
        permit: OwnedSemaphorePermit,
        revalidated: bool,
    },
    /// A classified 429: read for its classification fields, relayed as
    /// one frame byte-identical. Its headers are not re-taught (the
    /// observations stay unchanged).
    Classified429 {
        parts: http::response::Parts,
        collected: Option<Bytes>,
        permit: OwnedSemaphorePermit,
    },
    /// The second network failure — close the client connection.
    Network(String),
    /// A failure that is neither a network failure nor a status.
    Other(String),
    /// A 401 the exchange cannot recover from — the second one on
    /// an OAuth account, or the first on an API key. `errored_by_refresh`
    /// says the refresh engine already marked the account; `after_refresh`
    /// says a forced refresh preceded.
    Refused401 {
        after_refresh: bool,
        errored_by_refresh: bool,
    },
    /// The forced refresh sits out the transient floor.
    RefreshWait { until: OffsetDateTime },
}

/// The three retry budgets of one candidate's attempt loop — one
/// network retry, one throttle retry and one retry after a
/// forced refresh — stack on the first attempt to four attempts.
///
/// Each budget is a flag taken with `mem::replace`: the earlier counter form
/// (`n += u32::from(n == 0)`) came out wrong under the release profile
/// (rustc 1.90 and 1.95, aarch64-apple-darwin), where the unit test saw a
/// second network retry granted.
#[derive(Default)]
struct Retries {
    network_used: bool,
    throttle_used: bool,
    refresh_used: bool,
}

impl Retries {
    /// Retry once on a fresh connection.
    fn network_retry(&mut self) -> bool {
        !std::mem::replace(&mut self.network_used, true)
    }

    /// Retry once on the same account after an absorbable throttle.
    fn throttle_retry(&mut self) -> bool {
        !std::mem::replace(&mut self.throttle_used, true)
    }

    /// Retry once on the refreshed credential.
    fn refresh_retry(&mut self) -> bool {
        !std::mem::replace(&mut self.refresh_used, true)
    }

    /// The audit arithmetic: the first attempt plus every budget taken once.
    #[cfg(test)]
    fn total_attempts(&self) -> u32 {
        1 + u32::from(self.network_used)
            + u32::from(self.throttle_used)
            + u32::from(self.refresh_used)
    }
}

/// One candidate's attempts: admission waits, send, classify. One network
/// retry on a fresh connection, one throttle retry on the same account and
/// one retry after a forced refresh, never a second account.
async fn attempt_candidate(input: AttemptInput<'_>) -> Attempt {
    let AttemptInput {
        server,
        provider,
        mut capture,
        handle,
        display_name,
        method,
        uri,
        headers,
        body,
        model,
        settings,
        attempts,
        inline_wait_used,
    } = input;
    let throttle_absorb_seconds = settings.data_plane.throttle_absorb_seconds;
    let mut retries = Retries::default();
    // A throttle hold pauses the attempt at admission; once
    // the revalidation floor has passed, one waiting attempt is released as
    // the revalidation request and its outcome re-arms or
    // clears the hold for the rest.
    let mut released_as_revalidation = false;
    loop {
        // Injected fresh every iteration: a forced refresh replaced the
        // family mid-loop and the next attempt must carry it.
        let (attempt_headers, kind) = {
            let pool = server.pool.lock().expect("pool lock");
            let Some(account) = pool.get(handle) else {
                break Attempt::Other("the account left the pool mid-attempt".into());
            };
            let mut h = headers.clone();
            provider.inject_credential(&mut h, account);
            (h, account.kind())
        };
        // The slot is held from here until the response headers
        // arrive or the send fails — never for the streamed body.
        let slot = admit(server, handle, model, settings).await;
        if slot.revalidated {
            released_as_revalidation = true;
        }
        *attempts += 1;
        if let Some(c) = &mut capture {
            c.attempt(*attempts, method, uri, &attempt_headers, &body);
        }
        let request = build_request(method, uri, &attempt_headers, body.clone());
        let first_byte = Duration::from_secs(settings.data_plane.first_byte_timeout_seconds);
        let sent = server.upstream.send(request, first_byte).await;
        drop(slot);
        let failure = match sent {
            Err(SendError::Network(message)) if retries.network_retry() => {
                tracing::warn!(event = "upstream_network_failure", account = %display_name, error = %message, "retrying once on a fresh connection");
                continue;
            }
            Err(SendError::Network(message)) => break Attempt::Network(message),
            Err(SendError::Other(message)) => break Attempt::Other(message),
            Ok((response, permit)) => (response, permit),
        };
        let (response, permit) = failure;
        if response.status() == StatusCode::UNAUTHORIZED {
            // Once per exchange, the forced refresh precedes one
            // retry on the pool's newest credential.
            drop(permit);
            if kind == crate::pool::Kind::OAuth && retries.refresh_retry() {
                tracing::info!(event = "forced_refresh", account = %display_name, attempt = *attempts, "401 upstream; one forced refresh and one retry");
                match refresh::ensure_fresh(server, handle, Trigger::Forced).await {
                    Outcome::Ready => continue,
                    Outcome::Errored => {
                        break Attempt::Refused401 {
                            after_refresh: true,
                            errored_by_refresh: true,
                        };
                    }
                    // A 401 inside the transient floor starts no
                    // refresh; the exchange sits out the floor or refuses.
                    Outcome::Wait { until } => {
                        match settle_refresh_wait(
                            server,
                            handle,
                            display_name,
                            until,
                            Trigger::Forced,
                            inline_wait_used,
                        )
                        .await
                        {
                            Outcome::Ready => continue,
                            Outcome::Errored => {
                                break Attempt::Refused401 {
                                    after_refresh: true,
                                    errored_by_refresh: true,
                                };
                            }
                            Outcome::Wait { until } => break Attempt::RefreshWait { until },
                        }
                    }
                }
            }
            break Attempt::Refused401 {
                after_refresh: retries.refresh_used,
                errored_by_refresh: false,
            };
        }
        if response.status() != StatusCode::TOO_MANY_REQUESTS {
            break Attempt::Served {
                response,
                permit,
                revalidated: released_as_revalidation,
            };
        }
        // Classify before relaying. The body is read for
        // the classification fields only, then relayed byte-identical.
        let (response_parts, incoming) = response.into_parts();
        let collected = Limited::new(incoming, BODY_LIMIT)
            .collect()
            .await
            .ok()
            .map(|c| c.to_bytes());
        let classification = {
            let mut pool = server.pool.lock().expect("pool lock");
            pool.record_429(
                handle,
                model,
                &response_parts.headers,
                collected.as_deref(),
                OffsetDateTime::now_utc(),
            )
        };
        match classification {
            quota::Classification::Exhaustion { .. } => {
                server.mark_quota_dirty();
                let hold = {
                    let pool = server.pool.lock().expect("pool lock");
                    pool.quota_hold_end(handle, OffsetDateTime::now_utc())
                };
                let hold_end = hold.map(crate::timestamp::rfc3339);
                tracing::info!(event = "exhausted_relayed", account = %display_name, hold_end = hold_end.as_deref().unwrap_or("none"), "exhaustion 429 relayed with its retry-after");
                break Attempt::Classified429 {
                    parts: response_parts,
                    collected,
                    permit,
                };
            }
            quota::Classification::Throttle => {
                let seconds = throttle_seconds(&response_parts.headers)
                    .unwrap_or(RETRY_AFTER_DEFAULT)
                    .clamp(1, THROTTLE_CLAMP_MAX);
                if seconds <= throttle_absorb_seconds && retries.throttle_retry() {
                    tracing::info!(event = "throttle_wait", account = %display_name, seconds, "throttled; waiting once for the same account");
                    continue;
                }
                tracing::info!(event = "throttle_relayed", account = %display_name, seconds, "throttle beyond the absorb bound relayed");
                break Attempt::Classified429 {
                    parts: response_parts,
                    collected,
                    permit,
                };
            }
        }
    }
}

/// The upstream's `retry-after`, integer seconds, or none when absent or
/// unparseable — the hold arithmetic supplies the fallback.
fn throttle_seconds(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// The slot one admitted attempt holds on its account, released when
/// the upstream response headers arrive, the send fails, or the exchange is
/// dropped while the attempt is in flight.
struct Slot {
    server: Arc<Server>,
    handle: Uuid,
    /// Admission released this attempt as the revalidation request.
    revalidated: bool,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.server
            .pool
            .lock()
            .expect("pool lock")
            .release_slot(self.handle);
    }
}

/// Wait at admission until the account's throttle hold has ended
/// and the ramp, if one runs, has a free slot; a 100 ms poll beside the
/// pool's notify is the fail-open backstop. Under a pause, once the
/// revalidation floor has passed, the pool may release this waiting attempt
/// as the revalidation request. A client that leaves while
/// waiting drops this future and no attempt is made.
async fn admit(server: &Arc<Server>, handle: Uuid, model: Option<&str>, settings: &Config) -> Slot {
    let slot = |revalidated| Slot {
        server: Arc::clone(server),
        handle,
        revalidated,
    };
    let mut waiting_logged = false;
    loop {
        let now = OffsetDateTime::now_utc();
        let verdict = {
            let mut pool = server.pool.lock().expect("pool lock");
            pool.admit(handle, &settings.selection.ramp, now)
        };
        let notify = match verdict {
            Admit::Now => return slot(false),
            Admit::Paused { until, notify } => {
                let mut pool = server.pool.lock().expect("pool lock");
                if pool.release_waiting_revalidation(handle, model, &settings.quota, now) {
                    pool.take_slot(handle);
                    return slot(true);
                }
                if !waiting_logged {
                    tracing::debug!(event = "attempt_paused", account = %handle, until = %crate::timestamp::rfc3339(until), "attempt waits at admission for the throttle hold");
                }
                notify
            }
            Admit::Ramping { limit, notify } => {
                if !waiting_logged {
                    tracing::debug!(event = "attempt_ramped", account = %handle, limit, "attempt waits at admission for a ramp slot");
                }
                notify
            }
        };
        waiting_logged = true;
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            _ = notify.notified() => {}
        }
    }
}

/// Selection through the pool, then inline waits when nobody is eligible. A
/// bound exchange waits for nothing but its own account: no hold budget, the
/// exchange's one inline wait (shared with the refresh-wait) for a short
/// hold end, then the synthetic 429.
async fn select_or_wait(
    server: &Arc<Server>,
    settings: &Config,
    facts: &RequestFacts<'_>,
    session: Option<&SessionKey>,
    inline_wait_used: &mut bool,
) -> Result<selection::Choice, selection::Nobody> {
    let mut budget = settings.data_plane.hold_budget_seconds;
    loop {
        let now = OffsetDateTime::now_utc();
        let (expired, selected) = {
            let mut pool = server.pool.lock().expect("pool lock");
            let expired = pool.expire_quota(now);
            let selected = pool.select(facts, session, &settings.quota, &settings.selection, now);
            (expired, selected)
        };
        if expired {
            server.mark_quota_dirty();
        }
        let nobody = match selected {
            Ok(choice) => return Ok(choice),
            Err(nobody) => nobody,
        };
        if !nobody.clears {
            return Err(nobody);
        }
        let bound = nobody.named.is_some();
        let retry_after = retry_after_seconds(&nobody, now);
        let budgeted = !bound && settings.data_plane.hold_budget_seconds > 0;
        let wait = if budgeted {
            // Held on the hold budget, re-selecting at bounded
            // intervals; the budget bounds the whole hold, so a spent budget
            // answers at once — the inline wait is for exchanges
            // "without a hold budget".
            if budget == 0 {
                return Err(nobody);
            }
            let step = retry_after.min(HOLD_POLL_MAX).min(budget);
            budget -= step;
            step
        } else if !*inline_wait_used && retry_after <= INLINE_WAIT_MAX {
            // One inline wait rather than a synthetic 429 for a short hold end.
            *inline_wait_used = true;
            retry_after
        } else {
            return Err(nobody);
        };
        match nobody.named {
            Some(account) => tracing::info!(
                event = "bound_account_held",
                account = %account,
                seconds = wait,
                "bound account held; waiting once for its hold end"
            ),
            None => tracing::info!(
                event = "no_account_hold",
                reason = %reason_name(&nobody.reason),
                seconds = wait,
                "no eligible account; waiting before re-selection"
            ),
        }
        tokio::time::sleep(Duration::from_secs(wait)).await;
    }
}

/// Seconds until the soonest hold end or reset, rounded up so the
/// re-selection lands after the hold end, minimum 1, 60 when unknown.
fn retry_after_seconds(nobody: &selection::Nobody, now: OffsetDateTime) -> u64 {
    nobody
        .retry_at
        .map(|t| ((t - now).as_seconds_f64().ceil().max(1.0)) as u64)
        .unwrap_or(RETRY_AFTER_DEFAULT)
}

/// The reason's snake-case name, as the audit record and `status` spell it.
fn reason_name(reason: &NoService) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

fn refuse_errored_credential(exchange: &mut Exchange, handle: Uuid) -> Response<ResponseBody> {
    let display_name = exchange.display_name(handle);
    exchange.proxy_error(
        StatusCode::BAD_GATEWAY,
        format!(
            "the credential refresh for {display_name} was rejected; the operator must re-add the account"
        ),
        ErrorClass::Authentication,
    )
}

/// A candidate in refresh-wait. The floor's remainder ≤ 15 s and the
/// exchange's one inline wait unspent → wait it out, then start or join the
/// shared refresh operation and return its result. Otherwise refuse
/// at once; the caller turns the returned `Wait` into the synthetic 429.
async fn settle_refresh_wait(
    server: &Arc<Server>,
    handle: Uuid,
    display_name: &str,
    until: OffsetDateTime,
    trigger: Trigger,
    inline_wait_used: &mut bool,
) -> Outcome {
    let remainder = ((until - OffsetDateTime::now_utc())
        .as_seconds_f64()
        .ceil()
        .max(1.0)) as u64;
    if *inline_wait_used || remainder > INLINE_WAIT_MAX {
        return Outcome::Wait { until };
    }
    *inline_wait_used = true;
    tracing::info!(
        event = "refresh_wait_waited",
        account = %display_name,
        seconds = remainder,
        "waiting out the transient-failure floor inline"
    );
    tokio::time::sleep(Duration::from_secs(remainder)).await;
    refresh::ensure_fresh(server, handle, trigger).await
}

fn refuse_refresh_wait(
    exchange: &mut Exchange,
    handle: Uuid,
    until: OffsetDateTime,
) -> Response<ResponseBody> {
    let retry_after = ((until - OffsetDateTime::now_utc())
        .as_seconds_f64()
        .ceil()
        .max(1.0)) as u64;
    let display_name = exchange.display_name(handle);
    tracing::info!(event = "refresh_wait_refused", account = %display_name, retry_after, "its token refresh is waiting out a transient failure; refusing");
    // With no attempt made, no serving account and reason `refresh_wait`.
    if exchange.record.attempts == 0 {
        exchange.record.serving_account = None;
    }
    exchange.record.no_service_reason = Some("refresh_wait".to_string());
    let response = envelope::rate_limited(
        exchange.provider,
        &format!(
            "the token refresh for {display_name} is waiting out a transient failure; retry after the wait"
        ),
        retry_after,
    );
    exchange.respond(response, Some(ErrorClass::RateLimit))
}

/// The synthetic 429 for "nobody", naming the bound or pinned account when
/// the reason is that account's.
fn refuse_nobody(exchange: &mut Exchange, nobody: selection::Nobody) -> Response<ResponseBody> {
    let now = OffsetDateTime::now_utc();
    let named = nobody.named.map(|h| exchange.display_name(h));
    let (message, retry_after) = match (nobody.reason, named) {
        (NoService::PinnedUnavailable, name) => (
            format!(
                "the pinned account {} is unavailable",
                name.unwrap_or_else(|| "named by the pin".into())
            ),
            PINNED_RETRY_AFTER,
        ),
        (NoService::NoAccountConfigured, _) => (
            "no account is configured in this pool; the operator must add one".to_string(),
            RETRY_AFTER_DEFAULT,
        ),
        (NoService::AllDisabledOrErrored, Some(name)) => (
            format!(
                "the account bound to this session, {name}, is disabled or errored; the operator must act, or start a new session"
            ),
            RETRY_AFTER_DEFAULT,
        ),
        (NoService::AllDisabledOrErrored, None) => (
            "every account is disabled or errored; the operator must act".to_string(),
            RETRY_AFTER_DEFAULT,
        ),
        (NoService::AllHeldOrOverThreshold, Some(name)) => (
            format!(
                "the account bound to this session, {name}, is exhausted; retry after its reset or start a new session"
            ),
            retry_after_seconds(&nobody, now),
        ),
        (NoService::RouteExhausted, Some(name)) => (
            format!(
                "the route for this model does not allow {name}, the account bound to this session"
            ),
            retry_after_seconds(&nobody, now),
        ),
        (NoService::RouteExhausted, None) if nobody.clears => (
            "every account the route allows is exhausted; retry after the soonest reset"
                .to_string(),
            retry_after_seconds(&nobody, now),
        ),
        (NoService::RouteExhausted, None) => (
            "no account the route allows is usable; the operator must act".to_string(),
            retry_after_seconds(&nobody, now),
        ),
        (NoService::AllTried, Some(name)) => (
            format!(
                "{name}, the account bound to this session, was already tried in this exchange"
            ),
            retry_after_seconds(&nobody, now),
        ),
        (NoService::AllTried, None) => (
            "every account was already tried in this exchange".to_string(),
            retry_after_seconds(&nobody, now),
        ),
        (NoService::AllHeldOrOverThreshold, None) => {
            let n = exchange
                .server
                .pool
                .lock()
                .expect("pool lock")
                .accounts()
                .len();
            (
                format!("all {n} accounts are exhausted; retry after the soonest reset"),
                retry_after_seconds(&nobody, now),
            )
        }
    };
    tracing::info!(event = "no_account", reason = %reason_name(&nobody.reason), retry_after, "nobody eligible");
    let response = envelope::rate_limited(exchange.provider, &message, retry_after);
    exchange.respond(response, Some(ErrorClass::RateLimit))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each retry budget is single-use and the three of them stack on
    /// the first attempt — so a throttle retry and a network retry on top of
    /// the refreshed retry stay within four attempts.
    #[test]
    fn the_three_retry_budgets_stack_to_at_most_four_attempts() {
        let mut fresh = Retries::default();
        assert_eq!(fresh.total_attempts(), 1);

        // Each budget is single-use.
        assert!(fresh.network_retry());
        assert!(!fresh.network_retry());
        assert!(fresh.throttle_retry());
        assert!(!fresh.throttle_retry());
        assert!(fresh.refresh_retry());
        assert!(!fresh.refresh_retry());

        // The worst case: network retry + throttle retry + refreshed retry.
        let mut worst = Retries::default();
        assert!(worst.network_retry());
        assert!(worst.refresh_retry());
        assert!(worst.throttle_retry());
        assert_eq!(worst.total_attempts(), 4);
    }
}
