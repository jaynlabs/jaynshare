//! `jaynshare statusline`: Claude Code's
//! status-line command. It reads the payload on standard input, makes
//! exactly one client-status read keyed by the payload's session id,
//! prints one line and exits 0 — within 1.5 s whatever the server
//! does, never retrying, never writing to standard error, reading
//! no file but the config ones and writing none.

use std::io::{IsTerminal, Read};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::client;
use crate::picker::render::{Charset, percentage, sanitize};
use crate::provider::Provider;

/// Claude Code's: the only tool with this status line.
const PROVIDER: Provider = Provider::Anthropic;
/// A payload larger than this is no payload.
pub const MAX_PAYLOAD: usize = 64 * 1024;
/// The whole run, and the one request inside it.
const RUN_DEADLINE: Duration = Duration::from_millis(1_500);
const REQUEST_DEADLINE: Duration = Duration::from_millis(1_000);
pub(crate) const ACTIVE_ENV: &str = "JAYNSHARE_STATUSLINE";

/// What the one read produced.
#[derive(Debug, Clone, PartialEq)]
pub enum Snapshot {
    /// The status body, `session` present when a session id was sent.
    Answer(Value),
    /// No answer within the deadline, or the connection was refused.
    Offline,
    /// `401`/`403`: the enrollment is refused, not an outage.
    Refused,
    /// The config files are missing.
    NotEnrolled,
}

pub fn main() -> i32 {
    if std::env::var(ACTIVE_ENV).as_deref() != Ok("1") {
        return 0;
    }
    let started = Instant::now();
    let payload = read_payload(RUN_DEADLINE);
    let session = parse_payload(payload.as_deref());
    let colour = std::env::var_os("NO_COLOR").is_none();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let left = RUN_DEADLINE.saturating_sub(started.elapsed());
    let snapshot = runtime.block_on(async {
        tokio::time::timeout(left, fetch(session))
            .await
            .unwrap_or(Snapshot::Offline)
    });
    println!("{}", render(&snapshot, colour));
    // A stdin reader still blocked on a pipe that never closes must not hold
    // the process past the deadline.
    std::process::exit(0)
}

/// Standard input up to `MAX_PAYLOAD + 1` bytes, or `None` when there is
/// none (a terminal) or it did not arrive within `within`.
fn read_payload(within: Duration) -> Option<Vec<u8>> {
    if std::io::stdin().is_terminal() {
        return None;
    }
    let (send, receive) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let limit = (MAX_PAYLOAD + 1) as u64;
        let mut stdin = std::io::stdin().lock();
        let _ = stdin.by_ref().take(limit).read_to_end(&mut bytes);
        let _ = send.send(bytes);
        // Drain the rest so an oversized payload's writer never sees a broken
        // pipe; the process exits at the deadline whatever this thread does.
        let _ = std::io::copy(&mut stdin, &mut std::io::sink());
    });
    receive.recv_timeout(within).ok()
}

async fn fetch(session: Option<String>) -> Snapshot {
    let Ok(installation) = client::read_installation() else {
        return Snapshot::NotEnrolled;
    };
    let Ok(secret) = client::read_secret(&installation) else {
        return Snapshot::NotEnrolled;
    };
    match client::statusline_snapshot(&installation, &secret, session.as_deref(), REQUEST_DEADLINE)
        .await
    {
        Ok(body) => Snapshot::Answer(body),
        Err((5, _)) => Snapshot::Refused,
        Err(_) => Snapshot::Offline,
    }
}

/// The session id of the payload, or `None` for
/// an absent payload, one larger than `MAX_PAYLOAD`, one that is not JSON,
/// or an id that is empty, longer than 256 characters or outside
/// `[A-Za-z0-9._-]`.
pub fn parse_payload(payload: Option<&[u8]>) -> Option<String> {
    if payload.is_none_or(|p| p.len() > MAX_PAYLOAD) {
        return None;
    }
    let value: Value = serde_json::from_slice(payload?).ok()?;
    if !value.is_object() {
        return None;
    }
    let id = value["session_id"].as_str()?;
    if id.is_empty()
        || id.len() > 256
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return None;
    }
    Some(id.to_string())
}

/// The one line — `jaynshare →` the serving account, then every other
/// `PROVIDER` account's `five-hour%/weekly%` utilisation, then their active
/// session count; `offline`, the enrollment state for a refusal. Grey, and
/// only grey, when `colour` — the line never recolours the terminal — the
/// same content without it.
pub fn render(snapshot: &Snapshot, colour: bool) -> String {
    let line = match snapshot {
        Snapshot::Answer(body) => {
            let selected = body["session"]["serving_account_display_name"].as_str();
            let accounts: Vec<&Value> = body["accounts"]
                .as_array()
                .map(|accounts| accounts.iter().filter(|a| is_ours(a)).collect())
                .unwrap_or_default();
            let mut parts: Vec<String> = Vec::new();
            match selected {
                Some(name) => {
                    // The picked account first, marked by the arrow; the
                    // rest of the pool follows.
                    match accounts
                        .iter()
                        .copied()
                        .find(|a| a["display_name"].as_str() == Some(name))
                    {
                        Some(account) => parts.push(account_cell(account)),
                        None => parts.push(format!("{} ?/?", short_name(name))),
                    }
                    for account in &accounts {
                        if account["display_name"].as_str() != selected {
                            parts.push(account_cell(account));
                        }
                    }
                }
                None => {
                    parts.push("pending".to_owned());
                    for account in &accounts {
                        parts.push(account_cell(account));
                    }
                }
            }
            // A server without the per-account count has only the pool's.
            let active = accounts
                .iter()
                .map(|account| account["sessions_active"].as_u64())
                .sum::<Option<u64>>()
                .filter(|_| body["accounts"].is_array())
                .or_else(|| body["sessions"]["active"].as_u64())
                .unwrap_or(0);
            if active > 0 {
                parts.push(format!("{active} active"));
            }
            format!("jaynshare → {}", parts.join(" · "))
        }
        Snapshot::Offline => "jaynshare: offline".to_owned(),
        Snapshot::Refused => "jaynshare: enrollment refused, run jaynshare status".to_owned(),
        Snapshot::NotEnrolled => "jaynshare: not enrolled".to_owned(),
    };
    // Bright black — grey, calm, whatever the theme calls grey.
    if colour {
        format!("\u{1b}[90m{line}\u{1b}[0m")
    } else {
        line
    }
}

/// A 2.1.x server names no provider: its accounts are the default's.
fn is_ours(account: &Value) -> bool {
    account["provider"]
        .as_str()
        .map_or(PROVIDER.is_default(), |provider| {
            provider == PROVIDER.as_str()
        })
}

fn account_cell(account: &Value) -> String {
    format!(
        "{} {}/{}",
        short_name(account["display_name"].as_str().unwrap_or("unknown")),
        percentage(account["rate_limits"]["five_hour"].as_f64()),
        percentage(account["rate_limits"]["weekly"].as_f64()),
    )
}

/// A display name at most 16 characters, control characters removed, long
/// names cut with an ellipsis.
fn short_name(name: &str) -> String {
    sanitize(name, 16, Charset::Unicode)
}

#[cfg(test)]
mod render_tests {
    use super::*;
    use serde_json::json;

    fn strip(line: &str) -> String {
        let mut out = String::new();
        let mut chars = line.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                for escape in chars.by_ref() {
                    if escape == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn answer(serving: Option<&str>) -> Snapshot {
        Snapshot::Answer(json!({
            "session": serving.map(|name| json!({ "serving_account_display_name": name })),
            "accounts": [
                {
                    "display_name": "FSUB",
                    "rate_limits": { "five_hour": 0.12, "weekly": 0.34 },
                },
                {
                    "display_name": "FSUB2",
                    "rate_limits": { "five_hour": null, "weekly": 1.0 },
                },
            ],
        }))
    }

    #[test]
    fn the_picked_account_first_with_a_short_limits_pair() {
        assert_eq!(
            render(&answer(Some("FSUB")), false),
            "jaynshare → FSUB 12%/34% · FSUB2 0%/100%"
        );
    }

    #[test]
    fn no_serving_account_is_pending() {
        let body = json!({
            "accounts": [
                { "display_name": "FSUB", "rate_limits": { "five_hour": 0.12, "weekly": 0.34 } },
                { "display_name": "FSUB2", "rate_limits": { "five_hour": null, "weekly": 1.0 } },
            ],
            "sessions": { "active": 1 },
        });
        assert_eq!(
            render(&Snapshot::Answer(body), false),
            "jaynshare → pending · FSUB 12%/34% · FSUB2 0%/100% · 1 active"
        );
    }

    #[test]
    fn only_claude_code_accounts_and_their_sessions() {
        let body = json!({
            "session": { "serving_account_display_name": "FSUB" },
            "accounts": [
                {
                    "display_name": "FSUB",
                    "provider": "anthropic",
                    "rate_limits": { "five_hour": 0.12, "weekly": 0.34 },
                    "sessions_active": 1,
                },
                {
                    "display_name": "Codex Desk",
                    "provider": "codex",
                    "rate_limits": { "five_hour": 0.4, "weekly": 0.1 },
                    "sessions_active": 3,
                },
                {
                    "display_name": "FSUB2",
                    "provider": "anthropic",
                    "rate_limits": { "five_hour": null, "weekly": 1.0 },
                    "sessions_active": 1,
                },
            ],
            "sessions": { "active": 5 },
        });
        assert_eq!(
            render(&Snapshot::Answer(body), false),
            "jaynshare → FSUB 12%/34% · FSUB2 0%/100% · 2 active"
        );
    }

    #[test]
    fn a_selected_account_missing_from_the_catalogue_is_still_named() {
        let body = json!({
            "session": { "serving_account_display_name": "FSUB" },
            "accounts": [],
        });
        assert_eq!(
            render(&Snapshot::Answer(body), false),
            "jaynshare → FSUB ?/?"
        );
    }

    #[test]
    fn zero_active_sessions_name_nothing_and_long_names_overflow() {
        let body = json!({
            "session": { "serving_account_display_name": "Engineer (Pro plan)" },
            "accounts": [
                { "display_name": "Engineer (Pro plan)", "rate_limits": { "five_hour": 0.0, "weekly": 0.06 } },
            ],
            "sessions": { "active": 0 },
        });
        assert_eq!(
            render(&Snapshot::Answer(body), false),
            "jaynshare → Engineer (Pro p… 0%/6%"
        );
    }

    #[test]
    fn the_three_degraded_states() {
        assert_eq!(render(&Snapshot::Offline, false), "jaynshare: offline");
        assert_eq!(
            render(&Snapshot::Refused, false),
            "jaynshare: enrollment refused, run jaynshare status"
        );
        assert_eq!(
            render(&Snapshot::NotEnrolled, false),
            "jaynshare: not enrolled"
        );
    }

    #[test]
    fn colour_is_grey_and_strips_to_the_same_text() {
        let grey = |text: &str| format!("\u{1b}[90m{text}\u{1b}[0m");
        assert_eq!(
            render(&answer(Some("FSUB")), true),
            grey(&render(&answer(Some("FSUB")), false))
        );
        assert_eq!(
            strip(&render(&answer(Some("FSUB")), true)),
            render(&answer(Some("FSUB")), false)
        );
        assert_eq!(
            strip(&render(&Snapshot::Offline, true)),
            "jaynshare: offline"
        );
        assert_eq!(
            strip(&render(&Snapshot::Refused, true)),
            "jaynshare: enrollment refused, run jaynshare status"
        );
        assert_eq!(
            strip(&render(&Snapshot::NotEnrolled, true)),
            "jaynshare: not enrolled"
        );
    }
}

#[cfg(test)]
mod payload_tests {
    use super::*;
    use serde_json::json;

    const UUID: &str = "3f7a2c1e-0000-4000-8000-00000000c0de";

    fn payload(id: &str) -> Option<Vec<u8>> {
        Some(json!({ "session_id": id }).to_string().into_bytes())
    }

    #[test]
    fn none_payload_is_no_session() {
        assert_eq!(parse_payload(None), None);
    }

    #[test]
    fn oversize_payload_is_no_session() {
        let big = json!({"session_id": UUID, "pad": "x".repeat(64 * 1024)});
        assert!(big.to_string().len() > MAX_PAYLOAD);
        assert_eq!(parse_payload(Some(&big.to_string().into_bytes())), None);
    }

    #[test]
    fn not_json_is_no_session() {
        assert_eq!(parse_payload(Some(b"not json")), None);
    }

    #[test]
    fn non_object_json_is_no_session() {
        assert_eq!(parse_payload(Some(b"[1,2]")), None);
        assert_eq!(parse_payload(Some(b"\"hello\"")), None);
    }

    #[test]
    fn no_string_session_id_is_no_session() {
        assert_eq!(parse_payload(payload("").as_deref()), None, "empty");
        assert_eq!(
            parse_payload(Some(&json!({}).to_string().into_bytes())),
            None,
            "missing"
        );
        assert_eq!(
            parse_payload(Some(&json!({"session_id": 42}).to_string().into_bytes())),
            None,
            "a number"
        );
    }

    #[test]
    fn overlong_id_is_no_session() {
        assert_eq!(parse_payload(payload(&"a".repeat(257)).as_deref()), None);
    }

    #[test]
    fn id_outside_the_identifier_set_is_no_session() {
        assert_eq!(
            parse_payload(payload("abc\u{7}def").as_deref()),
            None,
            "control"
        );
        assert_eq!(parse_payload(payload("a b").as_deref()), None, "space");
        assert_eq!(parse_payload(payload("a/b").as_deref()), None, "slash");
        assert_eq!(parse_payload(payload("é").as_deref()), None, "non-ascii");
    }

    #[test]
    fn a_well_formed_id_is_kept() {
        assert_eq!(
            parse_payload(payload(UUID).as_deref()),
            Some(UUID.to_string())
        );
        assert_eq!(
            parse_payload(Some(statusline_shape_full().as_bytes())),
            Some(UUID.to_string())
        );
    }

    /// A payload in the status-line shape — extra keys and nested objects are ignored.
    fn statusline_shape_full() -> String {
        json!({
            "session_id": UUID,
            "version": "2.1.280",
            "model": { "id": "claude-haiku-4-5-20251001" },
        })
        .to_string()
    }
}
