//! The control verbs, their rendering and the prompts.

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::args::{
    AddArgs, ApiArgs, Cli, LoginArgs, ProbeArgs, ReplaceArgs, SecretChannel, SourceFlags,
    StatusArgs, SwitchArgs,
};
use super::control::Control;
use super::{Failure, Outcome, colour_wanted};

/// The bar's width, in cells, as the first release drew it.
const BAR_WIDTH: usize = 18;

/// One cell's colour on the bar's green→yellow→red gradient.
fn gradient(index: usize) -> (u8, u8, u8) {
    let t = index as f64 / (BAR_WIDTH - 1) as f64;
    let (from, to, p) = if t < 0.5 {
        ((35, 209, 96), (245, 185, 40), t * 2.0)
    } else {
        ((245, 185, 40), (239, 68, 68), (t - 0.5) * 2.0)
    };
    let mix = |a: u8, b: u8| (a as f64 + (b as f64 - a as f64) * p).round() as u8;
    (mix(from.0, to.0), mix(from.1, to.1), mix(from.2, to.2))
}

/// The colour decisions for one rendering: bold, dim and the bar
/// gradient on a terminal, the same characters plain otherwise.
struct Paint {
    colour: bool,
}

impl Paint {
    fn wrap(&self, code: &str, text: &str) -> String {
        if self.colour {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }
    fn bold(&self, text: &str) -> String {
        self.wrap("1", text)
    }
    fn dim(&self, text: &str) -> String {
        self.wrap("2", text)
    }
    /// A diagnostic line's label, dim and padded to the value column.
    fn label(&self, text: &str) -> String {
        self.dim(&format!("{text:<9}"))
    }
    fn gray(&self, text: &str) -> String {
        self.wrap("90", text)
    }
    fn green(&self, text: &str) -> String {
        self.wrap("32", text)
    }
    fn yellow(&self, text: &str) -> String {
        self.wrap("33", text)
    }
    fn red(&self, text: &str) -> String {
        self.wrap("31", text)
    }
    fn rgb(&self, (r, g, b): (u8, u8, u8), text: &str) -> String {
        if self.colour {
            format!("\x1b[38;2;{r};{g};{b}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }
}

/// The utilisation bar: `█` to the fill on the gradient, `░` beyond,
/// `?`s when the bucket's state is unknown.
fn usage_bar(ratio: Option<f64>, paint: &Paint) -> String {
    let Some(ratio) = ratio else {
        return format!("[{}]", paint.gray(&"?".repeat(BAR_WIDTH)));
    };
    let fill = (ratio.clamp(0.0, 1.0) * BAR_WIDTH as f64).round() as usize;
    let mut bar = String::new();
    for index in 0..BAR_WIDTH {
        if index < fill {
            bar.push_str(&paint.rgb(gradient(index), "█"));
        } else {
            bar.push_str(&paint.gray("░"));
        }
    }
    format!("[{bar}]")
}

/// A token count as `980`, `12k` or `1.2M`.
fn human_count(value: &Value) -> String {
    let n = value.as_u64().unwrap_or(0);
    // From 999.5k up, whole thousands would round to `1000k`.
    if n >= 999_500 {
        format!("{:.1}M", n as f64 / 1e6)
    } else if n >= 1_000 {
        format!("{:.0}k", n as f64 / 1e3)
    } else {
        n.to_string()
    }
}

/// `1h12m`, `2d3h`, `45s` — whole units, biggest first.
fn format_countdown(remaining: time::Duration) -> String {
    let s = remaining.whole_seconds().max(0);
    let (days, rest) = (s / 86_400, s % 86_400);
    let (hours, rest) = (rest / 3_600, rest % 3_600);
    let (minutes, seconds) = (rest / 60, rest % 60);
    if days > 0 {
        format!("{days}d{hours}h")
    } else if hours > 0 {
        format!("{hours}h{minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m{seconds}s")
    } else {
        format!("{seconds}s")
    }
}

/// The bucket's next release, from `reset` then `hold_end`, with the
/// word that names it.
fn future_countdown(b: &Value, now: OffsetDateTime) -> Option<(&'static str, String)> {
    for (member, word) in [("reset", "reset"), ("hold_end", "held")] {
        if let Some(at) = b[member].as_str().and_then(|value| {
            OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()
        }) && at > now
        {
            return Some((word, format_countdown(at - now)));
        }
    }
    None
}

/// One snapshot, rendered as the pool table: the heading, the routes,
/// one block per account with a utilisation bar per bucket, and the
/// default account. `--verbose` adds the diagnostics; a section flag
/// prints that section alone. `--check` never reaches the rendering:
/// `main` answers with the exit code alone.
pub(super) async fn status(control: &Control, cli: &Cli, args: &StatusArgs) -> Outcome {
    let body = control
        .expect(Method::GET, "/control/v1/status", None)
        .await?;
    if args.check {
        return Ok((Value::Null, String::new()));
    }
    let text = render_status(&body, cli, args);
    Ok((body, text))
}

fn render_status(body: &Value, cli: &Cli, args: &StatusArgs) -> String {
    let s = &body["status"];
    let paint = Paint {
        colour: colour_wanted(cli),
    };
    let now = OffsetDateTime::now_utc();
    let default_handle = s["default_account"]["handle"].as_str();
    let verbose = args.verbose;

    if args.accounts {
        let mut out = String::new();
        accounts_into(s, default_handle, &paint, verbose, now, &mut out);
        return out.trim_end().to_owned();
    }
    if args.routes {
        let mut out = String::new();
        routes_into(s, &paint, verbose, &mut out);
        return out.trim_end().to_owned();
    }
    if args.clients {
        let mut out = String::new();
        clients_into(s, &paint, &mut out);
        return out.trim_end().to_owned();
    }
    if args.config_section {
        let mut out = String::new();
        config_into(s, &paint, &mut out);
        return out.trim_end().to_owned();
    }

    let mut out = format!(
        "{} status\n",
        paint.yellow(&paint.bold(&format!(
            "◆ jaynshare {}",
            s["server"]["version"].as_str().unwrap_or("")
        )))
    );
    if verbose {
        server_into(s, &paint, &mut out);
        sessions_into(s, &paint, &mut out);
        probe_into(s, &paint, &mut out);
    }
    routes_into(s, &paint, verbose, &mut out);
    accounts_into(s, default_handle, &paint, verbose, now, &mut out);
    default_into(s, &paint, verbose, &mut out);
    if verbose {
        clients_into(s, &paint, &mut out);
        storage_into(s, &paint, &mut out);
        config_into(s, &paint, &mut out);
    }
    out.trim_end().to_owned()
}

fn server_into(s: &Value, paint: &Paint, out: &mut String) {
    let server = &s["server"];
    let mut line = format!(
        "  {}started {} listen {}{} control v{} telemetry {}",
        paint.label("server"),
        server["started_at"].as_str().unwrap_or(""),
        server["listen"].as_str().unwrap_or(""),
        if server["tls"].as_bool().unwrap_or(false) {
            " (tls)"
        } else {
            ""
        },
        server["control_api_versions"]
            .as_array()
            .map(|v| v
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(","))
            .unwrap_or_default(),
        server["telemetry_policy"].as_str().unwrap_or(""),
    );
    if let Some(origin) = server["upstream_origin_override"].as_str() {
        line += &format!(" {}", paint.red(&format!("UPSTREAM OVERRIDE {origin}")));
    }
    out.push_str(&line);
    out.push('\n');
    out.push_str(&format!(
        "  {}mode {} pinned {}\n",
        paint.label("egress"),
        server["egress"]["mode"].as_str().unwrap_or(""),
        server["egress"]["pinned_addresses"]
    ));
    out.push_str(&match s["capture"]["directory"].as_str() {
        Some(d) => format!("  {}ON, directory {d}\n", paint.label("capture")),
        None => format!("  {}off\n", paint.label("capture")),
    });
    if s["mitm"]["enabled"].as_bool().unwrap_or(false) {
        let m = &s["mitm"];
        let c = &m["counters"];
        out.push_str(&format!(
            "  {}ON listen {} ca {} fingerprint {} expires {}\n           tunnels intercepted {} tunnelled {}  counters intercepted {} opened {} refused 407 {} 403 {} unreachable {} handshakes failed {}\n",
            paint.label("mitm"),
            m["listen"].as_str().unwrap_or("null"),
            m["ca"]["state"].as_str().unwrap_or("null"),
            m["ca"]["fingerprint"].as_str().unwrap_or("null"),
            m["ca"]["not_after"].as_str().unwrap_or("null"),
            m["tunnels"]["intercepted"].as_u64().unwrap_or(0),
            m["tunnels"]["tunnelled"].as_u64().unwrap_or(0),
            c["intercepted_exchanges"].as_u64().unwrap_or(0),
            c["tunnels_opened"].as_u64().unwrap_or(0),
            c["connect_refused_407"].as_u64().unwrap_or(0),
            c["connect_refused_403"].as_u64().unwrap_or(0),
            c["connect_unreachable"].as_u64().unwrap_or(0),
            c["failed_handshakes"].as_u64().unwrap_or(0),
        ));
    } else {
        out.push_str(&format!("  {}off\n", paint.label("mitm")));
    }
}

fn routes_into(s: &Value, paint: &Paint, verbose: bool, out: &mut String) {
    out.push_str(&format!("{}\n", paint.bold("routes")));
    let routes = s["routes"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    if routes.is_empty() {
        out.push_str("  (none)\n");
    }
    for r in routes {
        let accounts = r["accounts"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|x| {
                        format!(
                            "{}{}",
                            x["display_name"].as_str().unwrap_or(""),
                            if x["eligible"].as_bool().unwrap_or(false) {
                                ""
                            } else {
                                "!"
                            }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let mut line = format!(
            "  {} {} → {}",
            r["name"].as_str().unwrap_or(""),
            r["patterns"]
                .as_array()
                .map(|p| p
                    .iter()
                    .map(|x| x.as_str().unwrap_or(""))
                    .collect::<Vec<_>>()
                    .join(" "))
                .unwrap_or_default(),
            accounts
        );
        if verbose {
            line += &format!(
                " bucket {} preference {} predicted {}",
                r["bucket"],
                r["preference"].as_str().unwrap_or("none"),
                r["predicted_target"].as_str().unwrap_or("none")
            );
        }
        out.push_str(&line);
        out.push('\n');
    }
    let blocked: Vec<&str> = s["blocked_models"]
        .as_array()
        .map(|b| b.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    if !blocked.is_empty() {
        out.push_str(&format!(
            "  {} {}\n",
            paint.dim("blocked"),
            blocked.join(" ")
        ));
    }
}

fn accounts_into(
    s: &Value,
    default_handle: Option<&str>,
    paint: &Paint,
    verbose: bool,
    now: OffsetDateTime,
    out: &mut String,
) {
    let accounts = s["accounts"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    if accounts.is_empty() {
        out.push_str(&format!("{}  (none)\n", paint.bold("accounts")));
        return;
    }
    for account in accounts {
        account_block(account, default_handle, paint, verbose, now, out);
    }
}

fn account_block(
    a: &Value,
    default_handle: Option<&str>,
    paint: &Paint,
    verbose: bool,
    now: OffsetDateTime,
    out: &mut String,
) {
    let name = a["display_name"].as_str().unwrap_or("");
    let kind = a["kind"].as_str().unwrap_or("");
    let is_default = default_handle.is_some_and(|h| a["handle"].as_str() == Some(h));
    let marker = if is_default {
        paint.green(">")
    } else {
        " ".to_owned()
    };
    let shown = if is_default {
        paint.bold(name)
    } else {
        name.to_owned()
    };
    let mut header = format!("{marker} {shown} ({kind}");
    if verbose {
        header += &format!(", prio {}", a["priority"]);
    }
    header.push(')');
    let health = a["health"]["state"].as_str().unwrap_or("unknown");
    header += &match health {
        "ready" => format!("  {}", paint.green(health)),
        "refreshing" | "refresh_wait" => format!("  {}", paint.yellow(health)),
        "errored" => format!(
            "  {}",
            paint.red(&format!(
                "{health} ({})",
                a["health"]["reason"].as_str().unwrap_or("")
            ))
        ),
        _ => format!("  {}", paint.gray(health)),
    };
    if !a["enabled"].as_bool().unwrap_or(true) {
        header += &format!("  {}", paint.gray("disabled"));
    }
    if verbose {
        header += &format!(
            "  {} sess  {} {}",
            a["sessions_active"],
            paint.dim("handle"),
            a["handle"].as_str().unwrap_or("")
        );
    }
    out.push_str(&header);
    out.push('\n');
    let buckets = a["buckets"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    for b in buckets {
        bucket_line(b, paint, now, out);
    }
    if a["eligibility"]["eligible"].as_bool() == Some(false) {
        let reason = a["eligibility"]["reason"].as_str().unwrap_or("");
        out.push_str(&match a["eligibility"]["reason_detail"].as_str() {
            Some(detail) if !detail.is_empty() => {
                format!("  {} {reason} {detail}\n", paint.yellow("ineligible"))
            }
            _ => format!("  {} {reason}\n", paint.yellow("ineligible")),
        });
    }
    if verbose {
        let usage = &a["usage"];
        out.push_str(&format!(
            "  {}{} in / {} out / {} req\n",
            paint.label("Usage"),
            human_count(&usage["input_tokens"]),
            human_count(&usage["output_tokens"]),
            usage["requests"]
        ));
        if let Some(outcome) = a["probe"]["outcome"].as_str() {
            let mut line = format!("  {}{outcome}", paint.label("Probe"));
            if let Some(at) = a["probe"]["finished_at"].as_str() {
                line += &format!(" {at}");
            }
            if let Some(error) = a["probe"]["error"].as_str() {
                line += &format!(" {}", paint.red(error));
            }
            out.push_str(&line);
            out.push('\n');
        }
        if let Some(end) = a["quota_holds"]["throttle_hold_end"].as_str() {
            let revalidation = if a["quota_holds"]["revalidation_allowed"].as_bool() == Some(true) {
                "allowed"
            } else {
                "withheld"
            };
            out.push_str(&format!(
                "  {}paused until {end} (revalidation {revalidation})\n",
                paint.label("Hold")
            ));
        }
        if a["ramp"]["active"].as_bool().unwrap_or(false) {
            out.push_str(&format!(
                "  {}limit {} since {}\n",
                paint.label("Ramp"),
                a["ramp"]["limit"],
                a["ramp"]["started_at"].as_str().unwrap_or("")
            ));
        }
    }
}

fn bucket_line(b: &Value, paint: &Paint, now: OffsetDateTime, out: &mut String) {
    let name = b["name"].as_str().unwrap_or("?");
    let label = paint.dim(&format!("{name:<14}"));
    let utilisation = b["utilisation"].as_f64().filter(|u| u.is_finite());
    let counter = match (b["limit"].as_f64(), b["remaining"].as_f64()) {
        (Some(limit), Some(remaining))
            if limit > 0.0 && remaining.is_finite() && (0.0..=limit).contains(&remaining) =>
        {
            Some(1.0 - remaining / limit)
        }
        _ => None,
    };
    let ratio = utilisation.or(counter);
    if b["state"].as_str() == Some("unknown") && ratio.is_none() {
        out.push_str(&format!(
            "  {label} {} {}\n",
            usage_bar(None, paint),
            paint.gray("unknown")
        ));
        return;
    }
    let mut line = format!(
        "  {label} {} {}",
        usage_bar(ratio, paint),
        ratio.map_or_else(|| "?".to_owned(), |r| format!("{:.0}%", r * 100.0))
    );
    if b["state"].as_str() == Some("exhausted") {
        line += &format!(" {}", paint.red("exhausted"));
    }
    if let Some((word, when)) = future_countdown(b, now) {
        line += &format!(" {} {when}", paint.dim(word));
    }
    out.push_str(&line);
    out.push('\n');
}

fn default_into(s: &Value, paint: &Paint, verbose: bool, out: &mut String) {
    let label = paint.bold("default");
    match &s["default_account"] {
        Value::Null => out.push_str(&format!("{label}  none\n")),
        d => {
            let name = s["accounts"]
                .as_array()
                .and_then(|a| a.iter().find(|x| x["handle"] == d["handle"]))
                .and_then(|x| x["display_name"].as_str())
                .unwrap_or("?");
            let mut line = format!(
                "{label}  {name} ({}) operator-chosen {}",
                d["handle"].as_str().unwrap_or(""),
                d["operator_chosen"]
            );
            if verbose {
                line += &format!(" since {}", d["since"].as_str().unwrap_or("null"));
            }
            out.push_str(&line);
            out.push('\n');
        }
    }
}

fn sessions_into(s: &Value, paint: &Paint, out: &mut String) {
    out.push_str(&format!(
        "  {}known {} active {} · {}\n",
        paint.label("sessions"),
        s["sessions"]["known"],
        s["sessions"]["active"],
        if s["sessions"]["distribution_enabled"]
            .as_bool()
            .unwrap_or(false)
        {
            "distributing"
        } else {
            "single-account"
        }
    ));
}

fn clients_into(s: &Value, paint: &Paint, out: &mut String) {
    out.push_str(&format!("{}\n", paint.bold("clients")));
    let clients = s["clients"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    if clients.is_empty() {
        out.push_str("  (none)\n");
    }
    for c in clients {
        out.push_str(&format!("  {}\n", client_row(c)));
    }
}

fn probe_into(s: &Value, paint: &Paint, out: &mut String) {
    out.push_str(&format!(
        "  {}enabled {} interval {}s pending {}\n",
        paint.label("probe"),
        s["usage_probe"]["enabled"],
        s["usage_probe"]["interval_seconds"],
        s["usage_probe"]["pending_reason"]
    ));
}

fn storage_into(s: &Value, paint: &Paint, out: &mut String) {
    let st = &s["storage"];
    out.push_str(&format!("{}\n", paint.bold("storage")));
    out.push_str(&format!(
        "  {}{} last write {}\n  {}{} {} bytes, {} retained\n  {}{} level {}\n",
        paint.label("state"),
        st["state"]["path"].as_str().unwrap_or(""),
        st["state"]["last_write"].as_str().unwrap_or("never"),
        paint.label("audit"),
        st["audit"]["path"].as_str().unwrap_or(""),
        st["audit"]["active_file_bytes"],
        st["audit"]["retained_files"],
        paint.label("log"),
        st["log"]["path"].as_str().unwrap_or(""),
        st["log"]["level"].as_str().unwrap_or(""),
    ));
}

fn config_into(s: &Value, paint: &Paint, out: &mut String) {
    let c = &s["configuration"];
    out.push_str(&format!("{}\n", paint.bold("config")));
    out.push_str(&format!(
        "  {}{} digest {} loaded {} last reload {}\n",
        paint.label("path"),
        c["path"].as_str().unwrap_or(""),
        c["digest"].as_str().unwrap_or(""),
        c["loaded_at"].as_str().unwrap_or(""),
        c["last_reload"]
    ));
}

/// Trigger a sweep; `--wait` polls the non-blocking snapshot until
/// this sweep has finished, then renders one outcome per account.
pub(super) async fn probe(control: &Control, args: &ProbeArgs) -> Outcome {
    let started = control
        .expect(Method::POST, "/control/v1/quota/probe", Some(&json!({})))
        .await?;
    if !args.wait {
        let at = started["started_at"].as_str().unwrap_or("").to_string();
        return Ok((started, format!("usage probe started at {at}")));
    }
    let started_at = started["started_at"]
        .as_str()
        .and_then(|value| {
            OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()
        })
        .ok_or_else(|| {
            Failure::local(
                10,
                "cli_incompatible_server",
                "probe start has no valid started_at",
            )
        })?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let snapshot = control
            .expect(Method::GET, "/control/v1/status", None)
            .await?;
        let finished = snapshot["status"]["usage_probe"]["last_finished"]
            .as_str()
            .and_then(|value| {
                OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()
            });
        if finished.is_some_and(|finished| finished >= started_at) {
            let rows = snapshot["status"]["accounts"]
                .as_array()
                .map(|accounts| {
                    accounts
                        .iter()
                        .map(|account| {
                            format!(
                                "{}  {}  {}  {}",
                                account["display_name"].as_str().unwrap_or(""),
                                account["probe"]["outcome"].as_str().unwrap_or("unknown"),
                                account["probe"]["finished_at"].as_str().unwrap_or("-"),
                                account["probe"]["error"].as_str().unwrap_or("")
                            )
                            .trim_end()
                            .to_string()
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default();
            return Ok((snapshot, rows));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Failure::local(
                1,
                "cli_internal",
                "usage probe did not finish within 120 seconds",
            ));
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// `state` or `state (reason)`.
pub(super) fn health_cell(a: &Value) -> String {
    let state = a["health"]["state"].as_str().unwrap_or("");
    match a["health"]["reason"].as_str() {
        Some(reason) => format!("{state} ({reason})"),
        None => state.to_string(),
    }
}

/// The account row: every fact the operator reads at a glance,
/// each bucket as `name=state@reset` (unknown says so, never `0%`).
pub(super) fn account_row(a: &Value) -> String {
    let buckets = a["buckets"]
        .as_array()
        .map(|b| b.iter().map(bucket_cell).collect::<Vec<_>>().join(" "))
        .unwrap_or_default();
    let health = health_cell(a);
    let eligibility = match a["eligibility"]["reason"].as_str() {
        Some(r) => format!(
            "ineligible: {r} {}",
            a["eligibility"]["reason_detail"].as_str().unwrap_or("")
        ),
        None => "eligible".to_string(),
    };
    // The pause and whether a revalidation may challenge it.
    let hold = match a["quota_holds"]["throttle_hold_end"].as_str() {
        Some(end) => format!(
            "paused until {end} (revalidation {})",
            if a["quota_holds"]["revalidation_allowed"].as_bool() == Some(true) {
                "allowed"
            } else {
                "withheld"
            }
        ),
        None => "no pause".to_string(),
    };
    let ramp = match a["ramp"]["limit"].as_u64() {
        Some(limit) => format!(
            "ramp limit {limit} since {}",
            a["ramp"]["started_at"].as_str().unwrap_or("")
        ),
        None => "no ramp".to_string(),
    };
    let probe = a["probe"]["outcome"].as_str().unwrap_or("not-run");
    format!(
        "{}  {}/{}  enabled {}  {health}  priority {}  {eligibility}  [{buckets}]  {hold}  {ramp}  sessions {}  usage in {} out {} req {}  probe {probe}  handle {}",
        a["display_name"].as_str().unwrap_or(""),
        a["kind"].as_str().unwrap_or(""),
        a["source_class"].as_str().unwrap_or(""),
        a["enabled"],
        a["priority"],
        a["sessions_active"],
        a["usage"]["input_tokens"],
        a["usage"]["output_tokens"],
        a["usage"]["requests"],
        a["handle"].as_str().unwrap_or(""),
    )
}

/// One quota bucket: utilisation for a known one (an API-key counter with
/// only a limit shows `n/limit`), `unknown` otherwise, then the reset and an
/// exhaustion hold's end.
fn bucket_cell(x: &Value) -> String {
    let utilisation = x["utilisation"]
        .as_f64()
        .map(|u| format!("{:.0}%", u * 100.0))
        .or_else(|| {
            let (limit, remaining) = (x["limit"].as_f64()?, x["remaining"].as_f64()?);
            Some(format!("{remaining}/{limit}"))
        });
    let value = match (x["state"].as_str().unwrap_or("unknown"), utilisation) {
        ("exhausted", Some(u)) => format!("exhausted({u})"),
        ("exhausted", None) => "exhausted".to_string(),
        (_, Some(u)) => u,
        (_, None) => "unknown".to_string(),
    };
    format!(
        "{}={value}{}{}",
        x["name"].as_str().unwrap_or(""),
        x["reset"]
            .as_str()
            .map(|r| format!("@{r}"))
            .unwrap_or_default(),
        x["hold_end"]
            .as_str()
            .map(|h| format!(" held-until {h}"))
            .unwrap_or_default(),
    )
}

pub(super) async fn account_list(control: &Control) -> Outcome {
    let body = control
        .expect(Method::GET, "/control/v1/accounts", None)
        .await?;
    let rows: Vec<String> = body["accounts"]
        .as_array()
        .map(|a| a.iter().map(account_row).collect())
        .unwrap_or_default();
    Ok((
        body,
        if rows.is_empty() {
            "(no accounts)".into()
        } else {
            rows.join("\n")
        },
    ))
}

pub(super) async fn account_show(control: &Control, reference: &str) -> Outcome {
    let body = control.resolve(reference).await?;
    let row = account_row(&body["account"]);
    Ok((body, row))
}

/// A secret enters through (a) a hidden prompt on the controlling
/// terminal, (b) the whole of standard input up to 64 KiB with `--stdin`, or
/// (c) an owner-only regular file with `--file` — never argv. One trailing
/// line ending is removed; the value lives only for the request.
pub(super) fn read_input(
    file: Option<&PathBuf>,
    stdin_flag: bool,
    prompt: &str,
) -> Result<String, Failure> {
    const LIMIT: usize = 64 * 1024;
    let mut bytes = Vec::new();
    if let Some(path) = file {
        // (c): a regular file readable by its owner only,
        // refused as a usage error before a byte is read.
        let regular = std::fs::metadata(path)
            .map(|m| m.is_file())
            .unwrap_or(false);
        if !regular {
            return Err(Failure::local(
                2,
                "cli_usage",
                format!("--file {}: not a regular file", path.display()),
            ));
        }
        crate::state::check_private(path)
            .map_err(|why| Failure::local(2, "cli_usage", format!("--file {why}")))?;
        std::fs::File::open(path)
            .and_then(|f| f.take(LIMIT as u64 + 1).read_to_end(&mut bytes))
            .map_err(|e| {
                Failure::local(
                    1,
                    "cli_internal",
                    format!("cannot read {}: {e}", path.display()),
                )
            })?;
    } else if stdin_flag {
        std::io::stdin()
            .take(LIMIT as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| Failure::local(1, "cli_internal", e.to_string()))?;
    } else if std::io::stdin().is_terminal() {
        // (a): echo off on the controlling terminal; the prompt goes to
        // standard error so `--json` output stays one document.
        eprint!("{prompt}");
        std::io::stderr().flush().ok();
        let line = rpassword::read_password().map_err(|e| {
            // Ctrl-C at the prompt ends by the signal convention,
            // not as an internal failure; a caller with a flow to cancel
            // does so before the exit.
            if e.kind() == std::io::ErrorKind::Interrupted {
                Failure::local(130, "cli_interrupted", "interrupted at the hidden prompt")
            } else {
                Failure::local(1, "cli_internal", format!("hidden prompt: {e}"))
            }
        })?;
        bytes = line.into_bytes();
    } else {
        return Err(Failure::local(
            2,
            "cli_usage",
            "no terminal for a hidden prompt; the value enters through a hidden prompt on a terminal, --stdin, or --file <path> (an owner-only file)",
        ));
    }
    if bytes.len() > LIMIT {
        return Err(Failure::local(
            9,
            "cli_rejected",
            "the secret input exceeds 64 KiB",
        ));
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    String::from_utf8(bytes)
        .map_err(|_| Failure::local(9, "cli_rejected", "the secret input is not UTF-8"))
}

/// The `credential` object of the add and replace verbs, from the one source
/// flag and the one secret channel where one applies.
fn credential_body(
    source: &SourceFlags,
    channel: &SecretChannel,
    platform_hint: Option<&str>,
) -> Result<Value, Failure> {
    let local_secret = channel.stdin || channel.file.is_some();
    if source.api_key {
        let key = read_secret(channel, "API key (hidden): ")?;
        return Ok(json!({ "source": "api_key", "api_key": key }));
    }
    if source.portable {
        let text = read_secret(channel, "portable credential object, one line (hidden): ")?;
        let object: Value = serde_json::from_str(&text)
            .map_err(|_| Failure::local(9, "cli_rejected", "the input is not a JSON object"))?;
        return Ok(json!({ "source": "portable_json", "credential": object }));
    }
    if source.claude_managed {
        // The server reads its own store; there is no secret to send.
        if local_secret {
            return Err(Failure::local(
                2,
                "cli_usage",
                "--claude-managed reads the credential on the server host; --stdin and --file do not apply",
            ));
        }
        let mut credential = json!({ "source": "claude_managed" });
        if let Some(hint) = platform_hint {
            credential["platform_hint"] = json!(hint);
        }
        return Ok(credential);
    }
    let path = source.server_file.as_ref().expect("clap group");
    if local_secret {
        return Err(Failure::local(
            2,
            "cli_usage",
            "--server-file names a file the server reads; --stdin and --file do not apply",
        ));
    }
    Ok(json!({ "source": "file", "path": path.display().to_string() }))
}

pub(super) fn read_secret(channel: &SecretChannel, prompt: &str) -> Result<String, Failure> {
    read_input(channel.file.as_ref(), channel.stdin, prompt)
}

pub(super) async fn account_add(control: &Control, args: &AddArgs) -> Outcome {
    if args.source.api_key && args.name.as_deref().is_none_or(str::is_empty) {
        return Err(Failure::local(
            2,
            "cli_usage",
            "--name is required with --api-key",
        ));
    }
    let credential = credential_body(&args.source, &args.channel, args.platform_hint.as_deref())?;
    let mut body = json!({ "credential": credential });
    if let Some(name) = &args.name {
        body["display_name"] = json!(name);
    }
    let result = control
        .expect(Method::POST, "/control/v1/accounts", Some(&body))
        .await?;
    let row = account_row(&result["account"]);
    Ok((result, row))
}

/// The replace verb: the reference becomes a handle, then the same credential body.
pub(super) async fn account_replace(
    control: &Control,
    reference: &str,
    args: &ReplaceArgs,
) -> Outcome {
    let handle = handle_of(control, reference).await?;
    let credential = credential_body(&args.source, &args.channel, args.platform_hint.as_deref())?;
    let result = control
        .expect(
            Method::POST,
            &format!("/control/v1/accounts/{handle}/credential"),
            Some(&json!({ "credential": credential })),
        )
        .await?;
    let row = account_row(&result["account"]);
    Ok((result, row))
}

pub(super) async fn account_rename(control: &Control, reference: &str, new_name: &str) -> Outcome {
    let handle = handle_of(control, reference).await?;
    let result = control
        .expect(
            Method::POST,
            &format!("/control/v1/accounts/{handle}/name"),
            Some(&json!({ "display_name": new_name })),
        )
        .await?;
    let row = account_row(&result["account"]);
    Ok((result, row))
}

/// `enable` is also the errored-state retry path.
pub(super) async fn account_availability(
    control: &Control,
    reference: &str,
    enabled: bool,
) -> Outcome {
    let handle = handle_of(control, reference).await?;
    let verb = if enabled { "enable" } else { "disable" };
    let result = control
        .expect(
            Method::POST,
            &format!("/control/v1/accounts/{handle}/{verb}"),
            Some(&json!({})),
        )
        .await?;
    let row = account_row(&result["account"]);
    Ok((result, row))
}

/// `switch <reference>` moves the default and reports `will_serve`;
/// `--route <name> <reference>` and `--route <name> --clear` steer a
/// route; no argument is the listing with the default marked.
pub(super) async fn switch(control: &Control, cli: &Cli, args: &SwitchArgs) -> Outcome {
    let (method, path, body) = match (&args.route, &args.reference, args.clear) {
        (Some(route), _, true) => (
            Method::DELETE,
            format!("/control/v1/selection/routes/{route}/preference"),
            None,
        ),
        (Some(route), Some(reference), false) => (
            Method::POST,
            format!("/control/v1/selection/routes/{route}/preference"),
            Some(json!({ "reference": handle_of(control, reference).await? })),
        ),
        (Some(_), None, false) => {
            return Err(Failure::local(
                2,
                "cli_usage",
                "switch --route takes an account reference or --clear",
            ));
        }
        (None, Some(reference), _) => (
            Method::POST,
            "/control/v1/selection/default".to_string(),
            Some(json!({ "reference": handle_of(control, reference).await? })),
        ),
        (None, None, _) => return switch_listing(control).await,
    };
    let result = control.expect(method, &path, body.as_ref()).await?;
    let route = args.route.as_deref().unwrap_or("");
    if args.clear {
        let human = match result["account"].as_str() {
            Some(handle) => format!("route {route} preference cleared (was {handle})"),
            None => format!("route {route} had no preference"),
        };
        return Ok((result, human));
    }
    let name = result["account"]["display_name"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let target = if args.route.is_some() {
        format!("route {route} prefers {name}")
    } else {
        format!("default is now {name}")
    };
    if result["will_serve"].as_bool().unwrap_or(false) {
        return Ok((result, format!("{target}; eligible")));
    }
    // An ineligible target is a warning, never an error; --quiet keeps
    // warnings under --quiet, so `cli.quiet` is not consulted.
    let reason = result["reason"]
        .as_str()
        .unwrap_or("ineligible")
        .to_string();
    let detail = result["reason_detail"].as_str().unwrap_or("").to_string();
    let _ = cli;
    eprintln!("warning: {name} will not serve: {reason} {detail}");
    Ok((result, format!("{target}; ineligible: {reason} {detail}")))
}

/// One row per account, the default marked with `*`.
async fn switch_listing(control: &Control) -> Outcome {
    let body = control
        .expect(Method::GET, "/control/v1/status", None)
        .await?;
    let default = body["status"]["default_account"]["handle"].clone();
    let rows: Vec<String> = body["status"]["accounts"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|x| {
                    let mark = if x["handle"] == default { "* " } else { "  " };
                    format!("{mark}{}", account_row(x))
                })
                .collect()
        })
        .unwrap_or_default();
    // The listing is the server's body as it answered, never reshaped.
    Ok((
        body,
        if rows.is_empty() {
            "(no accounts)".into()
        } else {
            rows.join("\n")
        },
    ))
}

/// A reference resolved to the handle the verb then names.
async fn handle_of(control: &Control, reference: &str) -> Result<String, Failure> {
    Ok(control.resolve(reference).await?["account"]["handle"]
        .as_str()
        .unwrap_or_default()
        .to_string())
}

/// Login: the URL goes to standard output first, states to
/// standard error, the pasted code (when one is wanted) to `…/code`.
pub(super) async fn account_login(control: &Control, cli: &Cli, args: &LoginArgs) -> Outcome {
    let mut body = json!({});
    if let Some(name) = args.name.as_deref() {
        body["display_name"] = json!(name);
    }
    let started = control
        .expect(Method::POST, "/control/v1/accounts/login", Some(&body))
        .await?;
    let id = started["operation_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let url = started["authorization_url"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let expires_at = started["expires_at"].as_str().and_then(|s| {
        OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
    });
    let manual = started["manual_code_required"].as_bool().unwrap_or(false);
    if args.no_wait {
        // The started body as the server answered it.
        return Ok((started, format!("{url}\noperation {id}")));
    }
    // The authorisation URL is standard output's first line; the one
    // JSON document keeps it inside the envelope instead.
    if !cli.json {
        println!("{url}");
        std::io::stdout().flush().ok();
    }
    if manual {
        // An interrupt (or any failure) at the paste stage
        // cancels the operation first, as the poll below does, so no flow
        // is left waiting on a person who has gone.
        let paste = match read_input(
            args.channel.file.as_ref(),
            args.channel.stdin,
            "paste the authorisation code or its full callback URL (hidden), or press Enter to wait for the browser: ",
        ) {
            Ok(paste) => paste,
            Err(f) => return Err(cancel_login(control, &id, f).await),
        };
        if !paste.is_empty()
            && let Err(f) = control
                .expect(
                    Method::POST,
                    &format!("/control/v1/operations/{id}/code"),
                    Some(&json!({ "code": paste })),
                )
                .await
        {
            return Err(cancel_login(control, &id, f).await);
        }
    }
    let result = poll_operation(control, cli, &id, expires_at).await?;
    let row = if result["operation"]["account"].is_null() {
        String::new()
    } else {
        account_row(&result["operation"]["account"])
    };
    Ok((result, row))
}

/// Post `…/cancel` for a login this process will no longer wait
/// on, then hand back the failure that ended the wait; an interrupt keeps
/// the signal convention's code and names the cancelled operation.
async fn cancel_login(control: &Control, id: &str, failure: Failure) -> Failure {
    let _ = control
        .expect(
            Method::POST,
            &format!("/control/v1/operations/{id}/cancel"),
            Some(&json!({})),
        )
        .await;
    if failure.code == 130 {
        Failure::local(
            130,
            "cli_interrupted",
            format!("interrupted; login operation {id} was cancelled"),
        )
    } else {
        failure
    }
}

/// The poll: one second apart, states on standard error, until the
/// operation ends or its `expires_at` passes; the result is the last
/// read's body. An interrupt cancels the operation first
/// (no flow left waiting on a person who has gone) and the process ends by
/// the signal convention.
pub(super) async fn poll_operation(
    control: &Control,
    cli: &Cli,
    id: &str,
    expires_at: Option<OffsetDateTime>,
) -> Result<Value, Failure> {
    let path = format!("/control/v1/operations/{id}");
    let mut last_state = String::new();
    loop {
        let tick = tokio::time::sleep(Duration::from_secs(1));
        tokio::select! {
            _ = tick => {}
            _ = tokio::signal::ctrl_c() => {
                let _ = control
                    .expect(Method::POST, &format!("{path}/cancel"), Some(&json!({})))
                    .await;
                return Err(Failure::local(
                    130,
                    "cli_interrupted",
                    format!("interrupted; login operation {id} was cancelled"),
                ));
            }
        }
        let body = control.expect(Method::GET, &path, None).await?;
        let operation = &body["operation"];
        let state = operation["state"].as_str().unwrap_or_default().to_string();
        if !cli.json && state != last_state {
            eprintln!("login {state}");
            last_state = state.clone();
        }
        match state.as_str() {
            "succeeded" => return Ok(body),
            "failed" => {
                return Err(Failure {
                    code: 9,
                    error: operation["error"].clone(),
                });
            }
            "cancelled" => {
                return Err(Failure::local(
                    8,
                    "cli_conflict",
                    format!("the login operation {id} was cancelled"),
                ));
            }
            _ => {}
        }
        if expires_at.is_some_and(|e| OffsetDateTime::now_utc() >= e) {
            return Err(Failure::local(
                8,
                "cli_conflict",
                format!("the login operation {id} expired before it completed"),
            ));
        }
    }
}

pub(super) async fn operation_show(control: &Control, id: &str) -> Outcome {
    let body = control
        .expect(Method::GET, &format!("/control/v1/operations/{id}"), None)
        .await?;
    let operation = &body["operation"];
    let mut human = format!("{} {}", operation["state"].as_str().unwrap_or("?"), id);
    if operation["account"].is_object() {
        human += &format!("\n{}", account_row(&operation["account"]));
    }
    Ok((body, human))
}

pub(super) async fn operation_code(
    control: &Control,
    id: &str,
    channel: &SecretChannel,
) -> Outcome {
    let paste = read_secret(channel, "authorisation code (hidden): ")?;
    let body = control
        .expect(
            Method::POST,
            &format!("/control/v1/operations/{id}/code"),
            Some(&json!({ "code": paste })),
        )
        .await?;
    Ok((body, format!("submitted to {id}")))
}

pub(super) async fn operation_cancel(control: &Control, id: &str) -> Outcome {
    let body = control
        .expect(
            Method::POST,
            &format!("/control/v1/operations/{id}/cancel"),
            Some(&json!({})),
        )
        .await?;
    Ok((body, format!("cancelled {id}")))
}

pub(super) async fn account_remove(control: &Control, cli: &Cli, reference: &str) -> Outcome {
    let account = control.resolve(reference).await?;
    let name = account["account"]["display_name"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let handle = account["account"]["handle"]
        .as_str()
        .unwrap_or("")
        .to_string();
    if !cli.yes && !confirm(&format!("remove account {name} ({handle})? [y/N] "))? {
        return Err(Failure::local(
            21,
            "cli_confirmation_required",
            "not confirmed",
        ));
    }
    let result = control
        .expect(
            Method::DELETE,
            &format!("/control/v1/accounts/{handle}"),
            None,
        )
        .await?;
    Ok((result, format!("removed {name}")))
}

/// The registry entry as one row: the lifecycle facts and the hash
/// algorithm, never a digest, code or secret.
fn client_row(c: &Value) -> String {
    let time = |key: &str| c[key].as_str().unwrap_or("null").to_string();
    format!(
        "{}  {}  generation {}  issued {}  expires {}  activated {}  revoked {}  hash {}",
        c["id"].as_str().unwrap_or(""),
        c["state"].as_str().unwrap_or(""),
        c["generation"],
        time("issued_at"),
        time("expires_at"),
        time("activated_at"),
        time("revoked_at"),
        c["hash_algorithm"].as_str().unwrap_or(""),
    )
}

/// The registry entry plus the display name, for `client show`.
fn client_show_row(c: &Value) -> String {
    format!(
        "{}  {}\n  {}",
        c["id"].as_str().unwrap_or(""),
        c["display_name"].as_str().unwrap_or(""),
        client_row(c)
    )
}

/// Three channels for one disclosure: a fresh `0600` file under
/// `--disclose-to` (and nothing printed but the path), inside `result` with
/// `--json`, or the labelled last line of the human output. The secret
/// member leaves `result` in every form the value is not carried in, and no
/// verb can print it again.
fn disclose(
    cli: &Cli,
    disclose_to: Option<&Path>,
    member: &str,
    label: &str,
    value: String,
    summary: &str,
    mut result: Value,
) -> Result<(Value, String), Failure> {
    if let Some(path) = disclose_to {
        super::bundle::write_disclosure(path, &value)?;
        if let Some(map) = result.as_object_mut() {
            map.remove(member);
            map.insert("disclosure_file".into(), json!(path.display().to_string()));
        }
        return Ok((result, path.display().to_string()));
    }
    if cli.json {
        return Ok((result, String::new()));
    }
    if let Some(map) = result.as_object_mut() {
        map.remove(member);
    }
    Ok((result, format!("{summary}\n{label}: {value}")))
}

fn disclosed_value(body: &Value, member: &str) -> Result<String, Failure> {
    body[member].as_str().map(str::to_owned).ok_or_else(|| {
        Failure::local(
            10,
            "cli_incompatible_server",
            format!("the response carries no {member}"),
        )
    })
}

// ------------------------------------------------------- the registry

/// `client list`: the registry in the server's order.
pub(super) async fn client_list(control: &Control) -> Outcome {
    let body = control
        .expect(Method::GET, "/control/v1/clients", None)
        .await?;
    let mut out = String::new();
    for c in body["clients"].as_array().into_iter().flatten() {
        out += &format!(
            "{}  {}  generation {}  {}\n",
            c["id"].as_str().unwrap_or(""),
            c["state"].as_str().unwrap_or(""),
            c["generation"],
            c["display_name"].as_str().unwrap_or(""),
        );
    }
    if out.is_empty() {
        out += "no client is enrolled\n";
    }
    Ok((body, out.trim_end().to_string()))
}

/// `client show <id>`: never a code or secret; a never-issued id is 6.
pub(super) async fn client_show(control: &Control, id: &str) -> Outcome {
    super::bundle::validate_client_id(id)?;
    let body = control
        .expect(Method::GET, &format!("/control/v1/clients/{id}"), None)
        .await?;
    Ok((body.clone(), client_show_row(&body["client"])))
}

/// `client issue <id> --name <display-name>`: one code, disclosed once.
pub(super) async fn client_issue(
    control: &Control,
    cli: &Cli,
    id: &str,
    name: &str,
    disclose_to: Option<&Path>,
) -> Outcome {
    super::bundle::validate_client_id(id)?;
    super::bundle::validate_display_name(name)?;
    let body = control
        .expect(
            Method::POST,
            "/control/v1/clients",
            Some(&json!({ "id": id, "display_name": name.trim() })),
        )
        .await?;
    let code = disclosed_value(&body, "enrollment_code")?;
    let entry = client_show_row(&body["client"]);
    let expiry = body["expires_at"].as_str().unwrap_or_default().to_string();
    disclose(
        cli,
        disclose_to,
        "enrollment_code",
        &format!("enrollment code (disclose once; expires {expiry})"),
        code,
        &entry,
        body,
    )
}

/// `client reissue <id>` without `--kit/--out`: a new pending
/// generation, its code disclosed once; the old code dies.
pub(super) async fn client_reissue(
    control: &Control,
    cli: &Cli,
    id: &str,
    disclose_to: Option<&Path>,
) -> Outcome {
    super::bundle::validate_client_id(id)?;
    let body = control
        .expect(
            Method::POST,
            &format!("/control/v1/clients/{id}/reissue"),
            Some(&json!({})),
        )
        .await?;
    let code = disclosed_value(&body, "enrollment_code")?;
    let entry = client_show_row(&body["client"]);
    let expiry = body["expires_at"].as_str().unwrap_or_default().to_string();
    disclose(
        cli,
        disclose_to,
        "enrollment_code",
        &format!("enrollment code (disclose once; expires {expiry})"),
        code,
        &entry,
        body,
    )
}

/// `client rotate <id>`: one new secret, the old dead on the next request
/// — reminded on standard error beside the disclosure.
pub(super) async fn client_rotate(
    control: &Control,
    cli: &Cli,
    id: &str,
    disclose_to: Option<&Path>,
) -> Outcome {
    super::bundle::validate_client_id(id)?;
    let body = control
        .expect(
            Method::POST,
            &format!("/control/v1/clients/{id}/rotate"),
            Some(&json!({})),
        )
        .await?;
    let secret = disclosed_value(&body, "client_secret")?;
    eprintln!("warning: the previous secret for {id} is refused from the next request");
    disclose(
        cli,
        disclose_to,
        "client_secret",
        "new client secret (disclose once)",
        secret,
        &client_show_row(&body["client"]),
        body,
    )
}

/// `client revoke <id>`: confirmation; an already-revoked id stays
/// exit 0, an unknown id is 6. The entry is read first: the prompt
/// names what is being killed, and an unknown id costs nothing.
pub(super) async fn client_revoke(control: &Control, cli: &Cli, id: &str) -> Outcome {
    super::bundle::validate_client_id(id)?;
    let shown = control
        .expect(Method::GET, &format!("/control/v1/clients/{id}"), None)
        .await?;
    let name = shown["client"]["display_name"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    if !cli.yes
        && !confirm(&format!(
            "revoke client {id} ({name})? every code and secret of it stops working [y/N] "
        ))?
    {
        return Err(Failure::local(
            21,
            "cli_confirmation_required",
            "not confirmed",
        ));
    }
    let body = control
        .expect(
            Method::POST,
            &format!("/control/v1/clients/{id}/revoke"),
            Some(&json!({})),
        )
        .await?;
    Ok((body, format!("revoked {id}")))
}

/// `client rename <id> <display-name>` (the display name is validated locally).
pub(super) async fn client_rename(control: &Control, id: &str, name: &str) -> Outcome {
    super::bundle::validate_client_id(id)?;
    super::bundle::validate_display_name(name)?;
    let body = control
        .expect(
            Method::POST,
            &format!("/control/v1/clients/{id}/name"),
            Some(&json!({ "display_name": name.trim() })),
        )
        .await?;
    Ok((body, format!("renamed {id} to {}", name.trim())))
}

/// Whether the remote-operator secret exists, for the set verb's
/// confirmation. There is no read that shows it, so the loopback command reads
/// the state document the configuration points at
/// — owner-only, on the operator's own machine. Unreadable means "not seen":
/// the server keeps the final word.
pub(super) fn operator_secret_exists(control: &Control) -> bool {
    control
        .state_path
        .as_deref()
        .and_then(|path| crate::state::load(path).ok())
        .is_some_and(|state| state.operator.is_some())
}

/// `operator secret set`: provision or rotate, disclose once; when
/// a secret exists a confirmation comes first — the old one dies at
/// once. From `--server` the CLI does not pre-empt the loopback
/// rule: the server answers `403 loopback_required` and that is 5.
pub(super) async fn operator_secret_set(
    control: &Control,
    cli: &Cli,
    disclose_to: Option<&Path>,
) -> Outcome {
    if cli.server.is_none() && !cli.yes && operator_secret_exists(control) {
        let ok = confirm(
            "an operator secret already exists; setting a new one kills it immediately. continue? [y/N] ",
        )?;
        if !ok {
            return Err(Failure::local(
                21,
                "cli_confirmation_required",
                "not confirmed",
            ));
        }
    }
    let body = control
        .expect(
            Method::POST,
            "/control/v1/operator/secret",
            Some(&json!({})),
        )
        .await?;
    let secret = disclosed_value(&body, "operator_secret")?;
    disclose(
        cli,
        disclose_to,
        "operator_secret",
        "operator secret (the pool's master key; the CLI never stores it)",
        secret,
        "provisioned the remote-operator secret",
        body,
    )
}

/// `operator secret remove`: after it only loopback callers are operators.
pub(super) async fn operator_secret_remove(control: &Control) -> Outcome {
    let body = control
        .expect(
            Method::DELETE,
            "/control/v1/operator/secret",
            Some(&json!({})),
        )
        .await?;
    Ok((
        body,
        "removed the remote-operator secret; only loopback callers are operators now".to_string(),
    ))
}

/// A typed confirmation: one line read on the
/// controlling terminal, trimmed; never skippable, so no terminal is 21.
pub(super) fn typed_line(prompt: &str) -> Result<String, Failure> {
    if !std::io::stdin().is_terminal() {
        return Err(Failure::local(
            21,
            "cli_confirmation_required",
            "this confirmation is interactive-only; run it on a terminal",
        ));
    }
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| Failure::local(1, "cli_internal", e.to_string()))?;
    // End-of-file echoes no newline: end the prompt's line here, so what
    // follows (a `--json` document included) starts on a line of its own.
    if !line.ends_with('\n') {
        eprintln!();
    }
    Ok(line.trim().to_string())
}

/// A skippable confirmation on the controlling terminal.
pub(super) fn confirm(prompt: &str) -> Result<bool, Failure> {
    if !std::io::stdin().is_terminal() {
        return Err(Failure::local(
            21,
            "cli_confirmation_required",
            "confirmation required; pass --yes when there is no terminal",
        ));
    }
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| Failure::local(1, "cli_internal", e.to_string()))?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

/// One request to the base-URL origin as the operator; the status
/// and headers to standard error, the body to standard output as it arrives.
/// `--account` adds the `pin.` intent token and `--prefer` the `pref.` token,
/// both base64url of the reference.
/// The request, built the same way for either role.
pub(super) type ApiRequest = (Method, Option<Bytes>, Vec<(HeaderName, HeaderValue)>);

/// Method, body, headers and the account intent token.
pub(super) fn api_request(args: &ApiArgs) -> Result<ApiRequest, Failure> {
    let method: Method = args
        .method
        .to_ascii_uppercase()
        .parse()
        .map_err(|_| Failure::local(2, "cli_usage", "METHOD is an HTTP method"))?;
    if !args.path.starts_with('/') {
        return Err(Failure::local(2, "cli_usage", "path starts with /"));
    }
    let body = if let Some(path) = &args.body_file {
        Some(Bytes::from(std::fs::read(path).map_err(|e| {
            Failure::local(
                1,
                "cli_internal",
                format!("cannot read {}: {e}", path.display()),
            )
        })?))
    } else if args.body_stdin {
        let mut bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|e| Failure::local(1, "cli_internal", e.to_string()))?;
        Some(Bytes::from(bytes))
    } else {
        None
    };
    let mut headers = Vec::new();
    for h in &args.headers {
        let (name, value) = h
            .split_once(':')
            .ok_or_else(|| Failure::local(2, "cli_usage", "--header takes name:value"))?;
        let name: HeaderName = name
            .trim()
            .parse()
            .map_err(|_| Failure::local(2, "cli_usage", format!("invalid header name {name:?}")))?;
        let value: HeaderValue = value
            .trim()
            .parse()
            .map_err(|_| Failure::local(2, "cli_usage", "invalid header value"))?;
        headers.push((name, value));
    }
    let intent = match (&args.account, &args.prefer) {
        (Some(reference), _) => Some((true, reference)),
        (None, Some(reference)) => Some((false, reference)),
        (None, None) => None,
    };
    if let Some((pin, reference)) = intent {
        let token = crate::data_plane::intent::encode_token(pin, reference);
        let value = HeaderValue::from_str(&token)
            .map_err(|_| Failure::local(2, "cli_usage", "the reference is not a header value"))?;
        headers.push((HeaderName::from_static("x-jaynshare-account"), value));
    }
    Ok((method, body, headers))
}

pub(super) async fn api(control: &Control, args: &ApiArgs, cli: &Cli) -> Outcome {
    let (method, body, headers) = api_request(args)?;
    let response = control.request(method, &args.path, body, &headers).await?;
    api_response(response, cli, &|why| control.unreachable(why)).await
}

/// The response side: status and headers on standard error and the body
/// streamed to standard output, or the `--json` document.
pub(super) async fn api_response(
    response: http::Response<hyper::body::Incoming>,
    cli: &Cli,
    interrupted: &dyn Fn(&str) -> Failure,
) -> Outcome {
    let (parts, mut response_body) = response.into_parts();
    let status = parts.status;
    let response_headers = parts.headers;
    if !cli.json {
        eprintln!("{status}");
        for (k, v) in &response_headers {
            eprintln!("{k}: {}", String::from_utf8_lossy(v.as_bytes()));
        }
        let mut stdout = std::io::stdout().lock();
        while let Some(frame) = response_body.frame().await {
            let frame =
                frame.map_err(|e| interrupted(&format!("response body interrupted: {e}")))?;
            if let Some(data) = frame.data_ref() {
                stdout
                    .write_all(data)
                    .and_then(|_| stdout.flush())
                    .map_err(|e| Failure::local(1, "cli_internal", e.to_string()))?;
            }
        }
        return Ok((Value::Null, String::new()));
    }
    let bytes = response_body
        .collect()
        .await
        .map_err(|e| interrupted(&format!("response body interrupted: {e}")))?
        .to_bytes();
    // Headers as one object; a repeated field joins with a comma.
    let mut header_map = serde_json::Map::new();
    for (k, v) in &response_headers {
        let value = String::from_utf8_lossy(v.as_bytes()).into_owned();
        match header_map.get_mut(k.as_str()) {
            Some(Value::String(existing)) => {
                existing.push_str(", ");
                existing.push_str(&value);
            }
            _ => {
                header_map.insert(k.as_str().to_string(), json!(value));
            }
        }
    }
    let body_value = match std::str::from_utf8(&bytes) {
        Ok(text) => json!(text),
        Err(_) => {
            json!({ "base64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes) })
        }
    };
    Ok((
        json!({ "status": status.as_u16(), "headers": header_map, "body": body_value }),
        String::new(),
    ))
}

/// Rotate the MITM certificate authority. Every enrolled
/// client needs the CA-update bundle afterwards, so the confirmation
/// says so before the old CA stops being the one clients trust.
pub(super) async fn ca_rotate(control: &Control, cli: &Cli) -> Outcome {
    if !cli.yes
        && !confirm(
            "rotate the MITM CA? every enrolled client needs the CA-update bundle before its next launch [y/N] ",
        )?
    {
        return Err(Failure::local(
            21,
            "cli_confirmation_required",
            "not confirmed",
        ));
    }
    let result = control
        .expect(Method::POST, "/control/v1/mitm/ca/rotate", Some(&json!({})))
        .await?;
    let line = format!(
        "rotated the CA; previous fingerprint {}, new fingerprint {} valid until {}",
        result["previous_fingerprint"].as_str().unwrap_or("(none)"),
        result["fingerprint"].as_str().unwrap_or(""),
        result["not_after"].as_str().unwrap_or(""),
    );
    // After the fingerprints, the reminder on standard error — in
    // `--json` mode too, where standard output is the envelope alone.
    eprintln!(
        "every enrolled client needs the CA-update bundle before its next MITM launch: ca update-bundle --out <dir>"
    );
    Ok((result, line))
}

/// `ca show`: the CA's fingerprint, expiry and state, without the
/// PEM; all `null` while MITM has never been enabled.
pub(super) async fn ca_show(control: &Control) -> Outcome {
    let body = control.expect(Method::GET, "/control/v1/ca", None).await?;
    let ca = &body["ca"];
    let result = json!({
        "fingerprint": ca["fingerprint"],
        "not_after": ca["not_after"],
        "state": ca["state"],
    });
    let line = match ca["fingerprint"].as_str() {
        Some(fingerprint) => format!(
            "CA {fingerprint}, valid until {} ({})",
            ca["not_after"].as_str().unwrap_or(""),
            ca["state"].as_str().unwrap_or(""),
        ),
        None => "MITM mode was never enabled: no CA".to_string(),
    };
    Ok((result, line))
}

/// `ca export`: the PEM on standard output or into a fresh file
/// (`0644`, exit 8 when the path exists). The CA is public, so this is not a
/// disclosure.
pub(super) async fn ca_export(control: &Control, out: Option<&Path>) -> Outcome {
    let ca = control.expect(Method::GET, "/control/v1/ca", None).await?["ca"].clone();
    let Some(pem) = ca["certificate_pem"].as_str().map(str::to_owned) else {
        return Err(Failure::local(
            8,
            "cli_no_ca",
            "MITM mode was never enabled: there is no CA to export",
        ));
    };
    let (result, line) = match out {
        None => (
            json!({
                "path": null,
                "certificate_pem": pem,
                "fingerprint": ca["fingerprint"],
                "not_after": ca["not_after"],
            }),
            pem,
        ),
        Some(path) => {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|_| {
                    Failure::local(
                        8,
                        "cli_output_exists",
                        format!("{} exists; choose another path", path.display()),
                    )
                })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o644))
                    .map_err(|e| {
                        Failure::local(1, "cli_internal", format!("{}: {e}", path.display()))
                    })?;
            }
            drop(file);
            std::fs::write(path, &pem).map_err(|e| {
                Failure::local(1, "cli_internal", format!("{}: {e}", path.display()))
            })?;
            (
                json!({
                    "path": path.display().to_string(),
                    "certificate_pem": pem,
                    "fingerprint": ca["fingerprint"],
                    "not_after": ca["not_after"],
                }),
                format!("wrote {}", path.display()),
            )
        }
    };
    Ok((result, line))
}
