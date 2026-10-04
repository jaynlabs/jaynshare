# Local acceptance profiling

Keep CI parallel. Sequential runs identify expensive cases, but include a
credential-leak sweep after every test, rather than mostly once per suite.
Start with a filtered subset: a full serial run can be much slower than CI,
and the reported durations include this harness cleanup, not just product work.
Do not run two acceptance processes concurrently: scenario directories are shared.

Build the optimized binary and the test runner first:

```sh
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 CARGO_PROFILE_RELEASE_LTO=off cargo build --locked --release --bin jaynshare
acceptance_bin=$(CARGO_PROFILE_TEST_DEBUG=line-tables-only cargo test --locked --test acceptance --no-run --message-format=json | jq -r 'select(.reason == "compiler-artifact" and .target.name == "acceptance") | .executable')
```

Run sequentially, with each case's wall-clock duration:

```sh
JAYNSHARE_BIN=target/release/jaynshare RUSTC_BOOTSTRAP=1 "$acceptance_bin" -Z unstable-options --report-time --test-threads=1 --color=never | tee target/acceptance-timings.log
```

The timing flags are unstable. Here `RUSTC_BOOTSTRAP` is scoped to the already-built
runner, not Cargo or compilation; the project's pinned compiler stays unchanged.
Append test names to profile a subset. Compare the same subset before and after;
use `--test-threads=8` to measure actual suite throughput.

For function-level flamegraphs, install the standalone sampling profiler
[samply](https://github.com/mstange/samply). Build with symbols locally:

```sh
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 CARGO_PROFILE_RELEASE_LTO=off cargo rustc --locked --release --bin jaynshare -- -C debuginfo=1 -C strip=none
JAYNSHARE_BIN=target/release/jaynshare samply record --save-only --unstable-presymbolicate --output target/acceptance-profile.json.gz "$acceptance_bin" --test-threads=1 acc::concurrent_prompts_share_one_refresh
samply load target/acceptance-profile.json.gz
```

Samply records child processes too, so the server and CLI work appears alongside
the harness. On macOS it also samples blocked threads, useful for finding waits.
Keep the generated symbol sidecar with the profile. Nothing is uploaded unless
you explicitly upload it in the viewer.

Fault-injected macOS children override `DYLD_INSERT_LIBRARIES`, which interferes
with samply's child tracking. Use a non-faulted case when profiling startup.
Sampling adds overhead: use unsampled runs for speed comparisons.
