//! The deployment layer: the release set and its verification, the
//! private-network preflight, the native server lifecycle and the OS trust
//! store. Every verb here is file-backed on the machine that runs it and
//! reports [`result::DeployResult`].
//!
//! Platform tools are invoked by name from `PATH` (`systemctl`, `nft`,
//! `security`, `certutil`, `icacls`, …), one wrapper function per tool, so
//! the test suite's fakes answer only what that wrapper asks.

pub mod address;
pub mod auto_update;
pub mod firewall;
pub mod native;
pub mod preflight;
pub mod release;
pub mod result;
pub mod systemd;
pub mod trust_store;
