# PaoPao Impactor fork fixes

Upstream baseline: claration/Impactor 2.6.3 at
`6eecd15f082f2ec003607dc437a43379be5e1d5f`. The authentication additions below
start from PaoPao fork commit `8ea9c77e7432749bc8da7cf8a10258e82d79df93`.

## Authentication compatibility

- GrandSlam SRP honors the response `sp` value. `s2k` derives PBKDF2 from the
  raw SHA-256 password digest, while `s2k_fo` derives it from the digest's
  lowercase ASCII hex. A missing value retains legacy `s2k` compatibility;
  unknown or malformed values fail explicitly.
- GrandSlam envelopes are parsed from response bytes, preserving binary plists.
  PaoPao diagnostics report only plist format, HTTP status, login stage and a
  fixed error category; response bodies, headers and credentials are excluded.
- Trusted-device notification delivery is best-effort because Apple's separate
  validation endpoint still verifies the entered code. SMS delivery errors
  remain fatal and do not fall through to verification.
- Plumesign retains the 2.6.3 `TwoFactorRequest` device/SMS selection flow and
  every interactive prompt still starts with the exact `Enter 2FA code:` prefix.

Authentication compatibility validation completed on 2026-09-17:

- `cargo test --locked -p plume_core -p plumesign` passed (7 tests across 3
  suites).
- `cargo test --locked -p plumesign -p omnisette --lib posix_macos::tests`
  passed (2 tests).
- `cargo build --release --locked -p plumesign` passed.

These automated regressions exercise the local `s2k`/`s2k_fo` derivation and
binary/XML plist fixtures. They do not constitute a real Apple password login,
or end-to-end server validation of Apple's `s2k_fo` or binary plist responses;
those live authentication paths remain unverified.

Exit conditions: remove the SRP/plist/trusted-device compatibility changes once
an upstream release provides equivalent behavior and these regressions pass
against it. Remove the PaoPao diagnostic markers and exact prompt contract only
after PaoPao Agent uses a stable structured authentication channel instead of
parsing process output.

## macOS ARM64 local Anisette fixes

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
behavior and the corresponding regressions pass.
