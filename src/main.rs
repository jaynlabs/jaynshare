//! `jaynshare`: one executable for the server and every role's verbs.

mod anthropic;
mod audit;
mod bundle;
mod capture;
mod cli;
mod client;
mod client_ca;
mod config;
mod control;
mod data_plane;
mod deploy;
mod identity;
mod launch;
mod logfile;
mod logging;
mod login;
mod mitm;
mod picker;
mod pool;
mod probe_client;
mod registry;
mod secret;
mod server;
mod settings;
mod state;
mod statusline;
mod timestamp;
mod title_hook;

fn main() {
    std::process::exit(cli::main());
}
