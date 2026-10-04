//! The launch environment as a plan: what the child
//! gets set and what it gets removed. `claude` and `codex` apply the plan to
//! the tool's process and `env` prints it quoted for a shell, so both are the
//! same rules. Each rule is one file; `build` composes them. The launch is
//! MITM mode only: base-URL mode can carry no client secret (the launcher
//! sets no bearer-token variable), so a remote Claude Code could not
//! authenticate through it.

pub mod direct;
pub mod mitm;
pub mod no_proxy;
pub mod timeout;

use super::Tool;
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
    pub tool: Tool,
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
    if inputs.tool == Tool::Claude {
        timeout::apply(
            &mut plan,
            inputs.hold_hint,
            inputs.inherited_timeout.as_deref(),
        );
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installation() -> ClientInstallation {
        ClientInstallation {
            directory: std::path::PathBuf::from("client"),
            client_id: "mac-1".into(),
            display_name: "Mac One".into(),
            base_url: "https://h:1".into(),
            proxy: Some("http://h:2".into()),
            ca_fingerprint: None,
            server_identity: None,
            no_proxy: vec![],
        }
    }

    fn pooled(tool: Tool) -> EnvPlan {
        build(&Inputs {
            tool,
            installation: &installation(),
            secret: "s",
            token: None,
            hold_hint: Some(541),
            inherited_timeout: None,
        })
    }

    fn removed(plan: &EnvPlan, name: &str) -> bool {
        plan.unset.iter().any(|n| n == name)
    }

    #[test]
    fn a_codex_launch_trusts_the_pool_through_codex_s_own_variables() {
        let plan = pooled(Tool::Codex);
        let ca = std::path::Path::new("client").join("ca.pem");
        assert_eq!(plan.get("CODEX_CA_CERTIFICATE"), ca.to_str());
        assert_eq!(plan.get("HTTPS_PROXY"), Some("http://:s@h:2"));
        for name in ["OPENAI_API_KEY", "CODEX_API_KEY", "OPENAI_BASE_URL"] {
            assert!(removed(&plan, name), "{name}");
        }
        assert_eq!(plan.get("NODE_EXTRA_CA_CERTS"), None);
        assert_eq!(plan.get("API_TIMEOUT_MS"), None, "Claude Code's alone");
    }

    #[test]
    fn a_claude_launch_keeps_its_variables_and_deadline() {
        let plan = pooled(Tool::Claude);
        assert!(plan.get("NODE_EXTRA_CA_CERTS").is_some());
        assert!(removed(&plan, "ANTHROPIC_BASE_URL"));
        assert_eq!(plan.get("CODEX_CA_CERTIFICATE"), None);
        assert_eq!(plan.get("API_TIMEOUT_MS"), Some("601000"));
    }

    #[test]
    fn direct_removes_each_tool_s_own_variables() {
        let mut codex = EnvPlan::default();
        direct::apply(&mut codex, Tool::Codex);
        for name in [
            "HTTPS_PROXY",
            "NO_PROXY",
            "CODEX_CA_CERTIFICATE",
            "OPENAI_API_KEY",
        ] {
            assert!(removed(&codex, name), "{name}");
        }
        assert!(!removed(&codex, "API_TIMEOUT_MS"));
        let mut claude = EnvPlan::default();
        direct::apply(&mut claude, Tool::Claude);
        for name in ["NODE_EXTRA_CA_CERTS", "ANTHROPIC_API_KEY", "API_TIMEOUT_MS"] {
            assert!(removed(&claude, name), "{name}");
        }
    }
}
