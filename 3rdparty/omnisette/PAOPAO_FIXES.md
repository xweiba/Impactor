# macOS ARM64 local Anisette fixes

Baseline: xweiba/Impactor `13272755aec353b2bdc1df3744d5f9b69a6d2d82`.

- Upstream loader: dadoum/android-loader, bigger_pages baseline
  `dfa86501afca7caa23d5ce15322ac7260d857485`.
- Fixed fork: xweiba/android-loader at
  `de8b13d2ff42419c463a7d54035ff20d5898b7d3` (pinned in Cargo.toml/lock).
  Merges host-page permissions and applies a consistent ELF load bias without
  creating writable executable pages. See the fork's FORK.md and four tests.
- Darwin file hooks now preserve errors, translate creation permissions and
  use the correct Android AArch64 stat ABI (128 bytes, not x86_64's 144).

Regression: `cargo test -p plumesign -p omnisette --lib posix_macos::tests`
passes both layout and real file I/O tests on macOS ARM64. Selecting plumesign
retains its dependency feature set; standalone upstream omnisette tests lack
Tokio macros and Chrono clock features.

On 2026-09-15 an account-free, disposable-directory probe called the real local
provider with the bundled arm64 libraries. First provisioning and a second
authentication-header generation both passed. No account/session data was used
and no generated header values were logged. The temporary probe is not shipped.
This validates local Anisette, not an entire IPA installation or other platforms.

Exit condition: move back to an upstream loader release once equivalent 16 KiB
page regressions pass; retain the Darwin ABI tests when updating omnisette.
