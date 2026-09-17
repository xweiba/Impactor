# macOS ARM64 local Anisette fixes

Baseline: claration/Impactor `6eecd15f082f2ec003607dc437a43379be5e1d5f`.

- Upstream loader: dadoum/android-loader, bigger_pages baseline
  `dfa86501afca7caa23d5ce15322ac7260d857485`.
- Fixed fork: xweiba/android-loader at
  `de8b13d2ff42419c463a7d54035ff20d5898b7d3` (pinned in Cargo.toml/lock).
  Merges host-page permissions and applies a consistent ELF load bias without
  creating writable executable pages. See the fork's FORK.md and four tests.
- Darwin file hooks now preserve errors, translate creation permissions and
  use the correct Android AArch64 stat ABI (128 bytes, not x86_64's 144).
- `PLUME_ANISETTE_V3_URL` can override the remote anisette v3 endpoint while
  retaining upstream's default URL when the variable is unset.
- Plumesign defaults to info logging, and saved-session restoration does not
  log the account email.
- Every interactive Plumesign 2FA prompt retains the exact
  `Enter 2FA code: ` prefix consumed by PaoPao Agent, while preserving the
  upstream device-code and SMS selection flow.
- Device lookup accepts either the usbmuxd numeric device ID or UDID.

The signed-IPA archive fix is now provided by upstream commit `6eecd15`: both
the CLI and GUI use `get_archive_based_on_path` with the extracted bundle path,
and ZIP entry separators are normalized. The earlier fork-only
`archive_signed_package` implementation has been removed.

Validation completed on 2026-09-17:

- `cargo test --locked -p plumesign` passed.
- `cargo build --release --locked -p plumesign` passed.
- The macOS ARM64 ABI and file-hook regression tests passed (`2 passed`).
- A local-provider probe used a fresh temporary state directory containing only
  the two ARM64 shared libraries, with remote fallback disabled. Initial
  provisioning and a second reuse both succeeded without SIGBUS.

No generated anisette values or account/session data are recorded here. The
temporary probe is not shipped. This validates local Anisette, not an entire IPA
installation or other platforms.

The real saved-session check subsequently reached Apple Developer API and returned
error 1100 (expired session), without SIGBUS. Renewing an expired Apple session
requires the user's normal login and possibly two-factor authentication.

Exit condition: move back to an upstream loader release once equivalent 16 KiB
page regressions pass; retain the Darwin ABI tests when updating omnisette. Drop
the remaining local changes individually when upstream provides equivalent
behavior and the corresponding regressions pass. The 2FA prompt prefix can be
dropped once PaoPao Agent no longer parses terminal output and uses a stable,
structured authentication handshake instead.
