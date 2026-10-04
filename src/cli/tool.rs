//! `claude`, `codex` and bare `jaynshare`: clap's flags become a
//! `launch::Request`; a refusal before the replacement exits with its
//! refusal code, and after it the exit code is the tool's.

use super::args::{LaunchArgs, Picker, ToolArgs};
use crate::launch::{self, IntentFlag};
use crate::picker;
use crate::provider::Provider;

pub(super) fn intent(args: &LaunchArgs) -> IntentFlag {
    if let Some(reference) = &args.account {
        IntentFlag::Account(reference.clone())
    } else if args.auto {
        IntentFlag::Auto
    } else if args.direct {
        IntentFlag::Direct
    } else {
        IntentFlag::Pick
    }
}

pub(super) fn picker_kind(picker: Option<Picker>) -> Option<picker::Kind> {
    picker.map(|p| match p {
        Picker::Keyboard => picker::Kind::Keyboard,
        Picker::Numbered => picker::Kind::Numbered,
    })
}

pub(super) fn launch(provider: Provider, args: &ToolArgs) -> i32 {
    run(launch::Request {
        provider: Some(provider),
        intent: intent(&args.launch),
        picker: picker_kind(args.picker),
        args: args.args.clone(),
    })
}

/// Bare `jaynshare`: the picker over every provider's accounts, then the
/// picked account's tool.
pub(super) fn pick() -> i32 {
    run(launch::Request {
        provider: None,
        intent: IntentFlag::Pick,
        picker: None,
        args: Vec::new(),
    })
}

fn run(request: launch::Request) -> i32 {
    match launch::run(request) {
        Ok(code) => code,
        Err(refusal) => {
            eprintln!("{}: {}", refusal.slug, refusal.message);
            refusal.code
        }
    }
}
