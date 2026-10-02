//! The harness's platform-boundary fixtures. Both live entirely outside the
//! product: the release binary is spawned unchanged and reads the platform
//! clock and the filesystem as it always does.
//!
//! The mechanism is the small interposition shim in `shim/clock_faults.c`,
//! compiled once at run time here and injected into the binary's children.
//! The product sees three `JAYNSHARE_`-prefixed environment variables naming
//! the shim's control files; they change no behaviour of the product itself,
//! and nothing of the shim is in the product's bytes.
//! Interposition is Unix-only; portable scenarios fall back to real waits on
//! Windows.

use std::io::{Read as _, Write as _};
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use crate::harness::{PathBuf, Uuid, fs};

fn shim_path() -> &'static PathBuf {
    static SHIM: OnceLock<PathBuf> = OnceLock::new();
    SHIM.get_or_init(|| {
        let source =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/acceptance/shim/clock_faults.c");
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/acceptance/shim");
        fs::create_dir_all(&directory).expect("shim output directory");
        let library = directory.join(if cfg!(target_os = "macos") {
            "libclock_faults.dylib"
        } else {
            "libclock_faults.so"
        });
        let mut compiler = Command::new("cc");
        if cfg!(target_os = "macos") {
            compiler.args(["-dynamiclib", "-O2"]);
        } else {
            compiler.args(["-shared", "-fPIC", "-O2", "-ldl"]);
        }
        let built = compiler
            .arg(&source)
            .arg("-o")
            .arg(&library)
            .status()
            .unwrap_or_else(|e| {
                panic!("the harness needs a C compiler for its interposition shim: {e}")
            });
        assert!(built.success(), "compiling the harness's shim failed");
        library
    })
}

/// One scenario's fault fixture: a directory of control files, and the shim
/// that reads them. Shared between the scenario's instance and its CLI runs.
pub(crate) struct Faults {
    directory: PathBuf,
}

impl Faults {
    pub(crate) fn new() -> Arc<Self> {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/acceptance")
            .join(format!("faults-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).expect("fault fixture directory");
        // An all-zero clock offset moves nothing; empty rename orders fire
        // nothing; an empty fsize order sets no limit.
        fs::write(directory.join("clock"), 0i64.to_le_bytes()).expect("clock control file");
        fs::write(directory.join("rename"), b"").expect("rename control file");
        fs::write(directory.join("fsize"), b"").expect("fsize control file");
        Arc::new(Self { directory })
    }

    /// Injects the shim into a child process. Every spawn a scenario makes
    /// under faults goes through this.
    pub(crate) fn inject(&self, command: &mut Command) {
        #[cfg(unix)]
        {
            command
                .env("JAYNSHARE_SHIM_CLOCK", self.directory.join("clock"))
                .env("JAYNSHARE_SHIM_RENAME", self.directory.join("rename"))
                .env("JAYNSHARE_SHIM_FSIZE", self.directory.join("fsize"));
            if cfg!(target_os = "macos") {
                command.env("DYLD_INSERT_LIBRARIES", shim_path());
            } else {
                command.env("LD_PRELOAD", shim_path());
            }
        }
        #[cfg(not(unix))]
        let _ = command;
    }

    /// Advances the injected clock immediately. Windows has no interposition
    /// shim, so it keeps the same coverage with a real wait.
    pub(crate) async fn elapse(&self, duration: Duration) {
        #[cfg(unix)]
        {
            self.set_clock_offset(self.clock_offset() as i128 + duration.as_nanos() as i128);
        }
        #[cfg(not(unix))]
        tokio::time::sleep(duration).await;
    }

    pub(crate) fn product_time(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc() + time::Duration::nanoseconds(self.clock_offset())
    }

    fn clock_offset(&self) -> i64 {
        let mut bytes = [0; size_of::<i64>()];
        fs::File::open(self.directory.join("clock"))
            .expect("clock control file")
            .read_exact(&mut bytes)
            .expect("read clock offset");
        i64::from_le_bytes(bytes)
    }

    /// Under the moved clock, the deadline the product sees at
    /// `anchor + seconds` is moved to now exactly, so the scenario asserts it
    /// exactly — no effect one tick before it, the effect at it. Call with
    /// the instant the product last saw the thing whose deadline is asserted;
    /// `seconds` is that deadline's length. One tick of granularity: the gap
    /// between the product's own timestamp and this call is inside the tick.
    pub(crate) fn set_deadline(&self, anchor: Instant, seconds: u64) {
        let elapsed = Instant::now() - anchor;
        let offset = seconds as i128 * 1_000_000_000 - elapsed.as_nanos() as i128;
        self.set_clock_offset(offset);
    }

    pub(crate) fn set_time(&self, target: time::OffsetDateTime) {
        self.set_clock_offset((target - time::OffsetDateTime::now_utc()).whole_nanoseconds());
    }

    fn set_clock_offset(&self, offset: i128) {
        let mut clock = fs::OpenOptions::new()
            .write(true)
            .open(self.directory.join("clock"))
            .expect("clock control file");
        clock
            .write_all(&(offset as i64).to_le_bytes())
            .expect("move the product's clock");
    }

    /// kills the process at the next rename whose destination ends
    /// with `suffix` — the boundary between the temporary write and the
    /// rename. Cleared by [`Self::clear_rename`].
    pub(crate) fn arm_rename_kill(&self, suffix: &str) {
        fs::write(self.directory.join("rename"), suffix).expect("arm the rename boundary");
    }

    pub(crate) fn clear_rename(&self) {
        fs::write(self.directory.join("rename"), b"").expect("clear the rename boundary");
    }

    /// the filled destination — from the next injected process on,
    /// every file write that would extend a file past `bytes` fails.
    pub(crate) fn fill_destination_at(&self, bytes: u64) {
        fs::write(self.directory.join("fsize"), bytes.to_string())
            .expect("arm the filled destination");
    }

    pub(crate) fn clear_fill(&self) {
        fs::write(self.directory.join("fsize"), b"").expect("clear the filled destination");
    }
}
