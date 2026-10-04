//! `account login` and `account list` as the enrolled client. The browser's
//! callback lands on this machine and is forwarded to the server, which
//! keeps the PKCE verifier and the tokens.

use std::io::{IsTerminal, Write};
use std::net::SocketAddr;
use std::time::Duration;

use http::Method;
use serde_json::{Value, json};
use tokio::net::TcpListener;

use super::args::{Cli, LoginArgs, LoginProvider};
use super::engineer::{client_failure_pair, installation, request, secret};
use super::verbs::{health_cell, login_body, provider_cell, read_input};
use super::{Failure, Outcome};
use crate::client::{self, ClientRequest};
use crate::login;

const ACCOUNTS: &str = "/control/v1/client/accounts";
/// OpenAI registered Codex's redirect on this one loopback port.
const CODEX_CALLBACK_PORT: u16 = 1455;

/// Log in an account this client owns: a new one, or one of its own again.
pub(super) async fn account_login(cli: &Cli, args: &LoginArgs) -> Outcome {
    if args.no_wait {
        return Err(Failure::local(
            2,
            "cli_usage",
            "--no-wait is the operator's: a client catches the browser's callback, so it waits",
        ));
    }
    let channel = Channel::open(cli)?;
    let port = if args.provider == Some(LoginProvider::Codex) {
        CODEX_CALLBACK_PORT
    } else {
        0
    };
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port)))
        .await
        .map_err(|e| internal(format!("cannot open the loopback callback listener: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| internal(format!("cannot read the callback listener's port: {e}")))?
        .port();
    let mut body = login_body(args);
    body["redirect_port"] = json!(port);
    let started = channel
        .call(Method::POST, &format!("{ACCOUNTS}/login"), Some(&body))
        .await?;
    let url = started["authorization_url"].as_str().unwrap_or_default();
    let flow = Flow {
        channel,
        id: started["operation_id"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    };
    let Some(state) = login::state_of(url) else {
        return Err(flow
            .abandon(Failure::local(
                10,
                "cli_incompatible_server",
                "the authorisation URL carries no state",
            ))
            .await);
    };
    if !cli.json {
        println!("{url}");
        std::io::stdout().flush().ok();
    }
    let forwarded = match flow.forward_paste(args, url).await {
        Ok(forwarded) => forwarded,
        Err(failure) => return Err(flow.abandon(failure).await),
    };
    let result = flow.wait(cli, &listener, &state, forwarded).await?;
    let row = owned_row(&result["operation"]["account"]);
    Ok((result, row))
}

/// The accounts this client added.
pub(super) async fn account_list(cli: &Cli) -> Outcome {
    let body = Channel::open(cli)?
        .call(Method::GET, &format!("{ACCOUNTS}/owned"), None)
        .await?;
    let rows: Vec<String> = body["accounts"]
        .as_array()
        .into_iter()
        .flatten()
        .map(owned_row)
        .collect();
    let human = if rows.is_empty() {
        "(no accounts of your own)".to_string()
    } else {
        rows.join("\n")
    };
    Ok((body, human))
}

/// Open the browser here, or read a pasted code: from `--stdin` or
/// `--file`, or at a hidden prompt when no browser opened.
fn open_or_paste(args: &LoginArgs, url: &str) -> Result<Option<String>, Failure> {
    let channel = &args.channel;
    let paste = if channel.stdin || channel.file.is_some() {
        read_input(channel.file.as_ref(), channel.stdin, "")?
    } else if !login::open_browser(url) && std::io::stdin().is_terminal() {
        read_input(
            None,
            false,
            "paste the authorisation code or its full callback URL (hidden), or press Enter to wait for the browser: ",
        )?
    } else {
        String::new()
    };
    Ok((!paste.is_empty()).then_some(paste))
}

fn owned_row(account: &Value) -> String {
    format!(
        "{}  {}  {}  {}",
        account["display_name"].as_str().unwrap_or(""),
        provider_cell(account),
        account["profile"]["email"].as_str().unwrap_or("-"),
        health_cell(account),
    )
}

fn internal(message: String) -> Failure {
    Failure::local(1, "cli_internal", message)
}

/// The installation's authenticated control channel.
struct Channel {
    request: ClientRequest,
    secret: String,
}

impl Channel {
    fn open(cli: &Cli) -> Result<Self, Failure> {
        let installation = installation()?;
        Ok(Self {
            secret: secret(&installation)?,
            request: request(&installation, cli)?,
        })
    }

    /// The answer's body; a refusal keeps the server's error object.
    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, Failure> {
        let (status, value) = self
            .request
            .call(method, path, Some(&self.secret), body)
            .await
            .map_err(client_failure_pair)?;
        if status.is_success() {
            return Ok(value);
        }
        let (code, message) = client::client_failure(status, &value);
        Err(match value["error"]["code"].as_str() {
            Some(_) => Failure {
                code,
                error: value["error"].clone(),
            },
            None => client_failure_pair((code, message)),
        })
    }
}

/// One started login, reached through the client's operation routes.
struct Flow {
    channel: Channel,
    id: String,
}

impl Flow {
    fn path(&self) -> String {
        format!("{ACCOUNTS}/operations/{}", self.id)
    }

    /// Forward a pasted code when there is one; whether there was.
    async fn forward_paste(&self, args: &LoginArgs, url: &str) -> Result<bool, Failure> {
        let Some(code) = open_or_paste(args, url)? else {
            return Ok(false);
        };
        self.forward(code).await.map(|()| true)
    }

    async fn forward(&self, code: String) -> Result<(), Failure> {
        self.channel
            .call(
                Method::POST,
                &format!("{}/code", self.path()),
                Some(&json!({ "code": code })),
            )
            .await
            .map(drop)
    }

    /// Cancel a login this process will no longer wait on, then hand back
    /// the failure that ended the wait; an interrupt names the operation.
    async fn abandon(&self, failure: Failure) -> Failure {
        let _ = self
            .channel
            .call(
                Method::POST,
                &format!("{}/cancel", self.path()),
                Some(&json!({})),
            )
            .await;
        if failure.code != 130 {
            return failure;
        }
        Failure::local(
            130,
            "cli_interrupted",
            format!("interrupted; login operation {} was cancelled", self.id),
        )
    }

    /// Forward the callback once it lands, and read the operation every
    /// second until it ends.
    async fn wait(
        &self,
        cli: &Cli,
        listener: &TcpListener,
        state: &str,
        mut forwarded: bool,
    ) -> Result<Value, Failure> {
        let callback = login::await_callback(listener, state);
        tokio::pin!(callback);
        let mut last_state = String::new();
        loop {
            tokio::select! {
                query = &mut callback, if !forwarded => {
                    let sent = match query {
                        Ok(query) => self.forward(query).await,
                        Err(why) => Err(internal(why)),
                    };
                    if let Err(failure) = sent {
                        return Err(self.abandon(failure).await);
                    }
                    forwarded = true;
                }
                _ = tokio::signal::ctrl_c() => {
                    let interrupted = Failure::local(130, "cli_interrupted", "interrupted");
                    return Err(self.abandon(interrupted).await);
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    let body = self.channel.call(Method::GET, &self.path(), None).await?;
                    let operation = &body["operation"];
                    let state = operation["state"].as_str().unwrap_or_default();
                    if !cli.json && state != last_state {
                        eprintln!("login {state}");
                        last_state = state.to_string();
                    }
                    match state {
                        "succeeded" => return Ok(body),
                        "failed" => return Err(Failure { code: 9, error: operation["error"].clone() }),
                        "cancelled" => {
                            return Err(Failure::local(
                                8,
                                "cli_conflict",
                                format!("the login operation {} was cancelled", self.id),
                            ));
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
