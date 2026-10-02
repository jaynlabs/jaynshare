//! The launch environment as a plan: what the child
//! gets set and what it gets removed. `claude` applies the plan to Claude Code's
//! process and `env` prints it quoted for a shell, so both are the
//! same rules. Each rule is one file; `build` composes them. The launch is
//! MITM mode only: base-URL mode can carry no client secret (the launcher
//! sets no bearer-token variable), so a remote Claude Code could not
//! authenticate through it.

pub mod direct;
pub mod mitm;
pub mod no_proxy;
pub mod timeout;

use crate::client::ClientInstallation;

/// The child's environment changes, in the order they were decided. A name
/// is never both set and unset: the last decision wins.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EnvPlan {
    pub set: Vec<(String, String)>,
    pub unset: Vec<String>,
}

impl EnvPlan {
    pub fn set(&mut self, name: &str, value: impl Into<String>) {
        self.unset.retain(|n| n != name);
        self.set.retain(|(n, _)| n != name);
        self.set.push((name.to_string(), value.into()));
    }

    pub fn unset(&mut self, name: &str) {
        self.set.retain(|(n, _)| n != name);
        if !self.unset.iter().any(|n| n == name) {
            self.unset.push(name.to_string());
        }
    }

    #[cfg(test)] // the env-rule unit tests read the plan with it
    pub fn get(&self, name: &str) -> Option<&str> {
        self.set
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// The four proxy spellings, in precedence order.
pub const PROXY_VARIABLES: [&str; 4] = ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"];
/// The no-proxy spellings.
pub const NO_PROXY_VARIABLES: [&str; 2] = ["NO_PROXY", "no_proxy"];

/// What every rule may read.
pub struct Inputs<'a> {
    pub installation: &'a ClientInstallation,
    pub secret: &'a str,
    /// A specific account token, `None` for automatic selection.
    pub token: Option<&'a str>,
    /// The hold hint in seconds, `None` when the snapshot was unreadable.
    pub hold_hint: Option<u64>,
    /// The inherited `API_TIMEOUT_MS`, if any (never lowered).
    pub inherited_timeout: Option<String>,
}

/// The plan for a pooled launch.
pub fn build(inputs: &Inputs<'_>) -> EnvPlan {
    let mut plan = EnvPlan::default();
    // Consumed by the launcher, never seen by the child.
    plan.unset("JAYNSHARE_ACCOUNT");
    mitm::apply(&mut plan, inputs);
    no_proxy::apply(&mut plan, &inputs.installation.no_proxy);
    timeout::apply(
        &mut plan,
        inputs.hold_hint,
        inputs.inherited_timeout.as_deref(),
    );
    plan
}
