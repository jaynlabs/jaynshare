//! `--direct` removes every launch-set variable — the four
//! proxy spellings, the no-proxy list, the tool's CA variable and its own
//! upstream and credential variables, and for Claude Code `API_TIMEOUT_MS` —
//! even when the shell exported them.

use super::EnvPlan;
use crate::launch::Tool;

pub fn apply(plan: &mut EnvPlan, tool: Tool) {
    for name in super::PROXY_VARIABLES {
        plan.unset(name);
    }
    for name in super::NO_PROXY_VARIABLES {
        plan.unset(name);
    }
    plan.unset(tool.ca_variable());
    for name in tool.upstream_variables() {
        plan.unset(name);
    }
    if tool == Tool::Claude {
        // The launcher cannot tell whose `API_TIMEOUT_MS` it is, so it
        // goes too.
        plan.unset("API_TIMEOUT_MS");
    }
}
