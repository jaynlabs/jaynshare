//! Acceptance suite. Black-box only: the shipped binary through its CLI and
//! its base-URL listener, a fake Anthropic upstream reached through a loopback
//! override, and the harness's observation surfaces.

#![allow(clippy::items_after_test_module)]
// Scenarios that observe Unix modes or signals compile out elsewhere, leaving
// their helpers unused there (the Windows cross-check).
#![cfg_attr(
    not(unix),
    allow(dead_code, unused_imports, unused_mut, unreachable_code)
)]

mod acc;
mod acp;
mod ca_follow;
mod cfg;
mod cli;
mod client_fx;
mod clt;
mod ctl;
mod cxp_line;
mod cxp_picker;
mod cxp_run;
mod cxp_settings;
mod cxp_status;
mod dep_auto_update;
mod dep_install;
mod dep_native;
mod dep_net;
mod dep_release;
mod dpl;
mod enrol;
mod fake_tools;
mod faults;
mod follow;
mod harness;
mod idt;
mod join;
mod leaks;
mod linux_fx;
mod linuxbox;
mod mtm;
mod own;
mod profile_fx;
mod proxy;
mod qta;
mod release_fx;
mod sec;
mod sel;
