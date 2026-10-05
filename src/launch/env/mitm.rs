//! MITM mode — the four proxy variable spellings carrying
//! `http://<token>:<secret>@<proxy origin>`, the tool's CA variable
//! at the installation's `ca.pem` as a native path, and the tool's own
//! upstream and credential variables removed. The secret travels as the
//! proxy URL's password; no bearer-token variable.

use super::{EnvPlan, Inputs, PROXY_VARIABLES};

pub fn apply(plan: &mut EnvPlan, inputs: &Inputs<'_>) {
    let origin = inputs.installation.proxy.as_deref().unwrap_or_default();
    let authority = origin
        .strip_prefix("http://")
        .unwrap_or(origin)
        .trim_end_matches('/');
    let user = inputs
        .token
        .map(crate::client::percent_encode)
        .unwrap_or_default();
    let password = crate::client::percent_encode(inputs.secret);
    let url = format!("http://{user}:{password}@{authority}");
    for name in PROXY_VARIABLES.iter() {
        plan.set(name, url.clone());
    }
    plan.set(
        inputs.tool.ca_variable,
        inputs
            .installation
            .directory
            .join("ca.pem")
            .display()
            .to_string(),
    );
    for name in inputs.tool.upstream_variables {
        plan.unset(name);
    }
}
