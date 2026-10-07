# Changelog

All notable changes to bootintel-cli are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) with the policy documented in the design doc §14 Q6:

- **MAJOR** — any CLI flag renamed or removed; any output-format schema change; any exit-code policy change.
- **MINOR** — new detector; new subcommand; new flag; new output format.
- **PATCH** — bug fix; internal refactor; docs; no user-visible behavior change.

## [Unreleased]

### Added
- **`bootintel submit`**: save a boot log to your BootIntel account as a persisted
  scan and download the server-side artifacts in one step: the CycloneDX 1.6 SBOM
  (`--sbom`), evidence pack (`--evidence`), PDF report (`--pdf`) and JSON report
  (`--json-report`). `--json` prints the scan id and written paths for scripting.

  Separate from `scan --api` on purpose. That posts to `/analysis/scan`, which the
  server documents as stateless and returns a freshly minted uuid naming no row,
  so there is nothing to export from; artifacts are built from a real scan, which
  only `POST /scans/` creates. A saved scan consumes the monthly quota, so this is
  opt-in rather than a flag, and the command says what it is about to spend
  immediately before spending it.

  Requires **Pro** or higher. The export endpoints are gated at Researcher, but
  API-key authentication is itself Pro-gated, so a Researcher account can download
  these from the dashboard and not from here.

  Reuses an existing device with the same name rather than creating one per run,
  because the server accepts duplicates and a nightly CI job would otherwise add
  a device a day.

## [0.13.0] — 2026-09-29 — read boot logs from your own assistant

### Added
- **`bootintel mcp`**: serve the offline analysis to an MCP client over stdio, so
  an assistant can do the reasoning half of reading a boot log while this binary
  does the reading half. Four tools: `scan_log`, `boot_chain_verdict`,
  `list_detectors`, `sample_log`.

  It runs locally on purpose. The model is the operator's own, under whatever
  agreement they already work under, and no capture leaves the machine. A hosted
  version would have to receive the log, which is the thing an NDA-bound
  consultancy cannot do.

  **Every tool is read-only.** None opens a serial port, writes to a device, or
  reaches the network, and a test asserts the tool list rather than trusting
  that, so adding a write is a deliberate edit rather than something that
  arrives unnoticed. Captures are passed as text rather than a path, so the
  caller decides what is disclosed.

  The honesty the engine is careful about survives the trip: an empty finding
  list says that the capture was not recognised rather than that the device is
  clean, and the verdict names the value each entry was read from.

## [0.12.0] — 2026-09-29 — the dashboard can take the prompt too

### Added
- **`--interrupt-autoboot` works with `--tui`.** It was refused there rather than
  silently ignored, which was the right call while it was unwired, but it left
  the dashboard as the one mode that could not take the prompt.

  The verdicts appear at the top of the findings pane, above the detector
  findings, because they were read from the device at the prompt and that is
  better evidence than anything matched out of the scrollback. Operator notes go
  to the status bar and the miss explanation stays there long enough to act on.

  The tool's own notes never pass through the analyzer. Feeding them back would
  let a detector match bootintel's output and report it as evidence about the
  device, which is asserted in a test rather than left to care.

## [0.11.0] — 2026-09-28 — board info and the flash partition table

### Added
- **`bootintel verdict` now reports board info and the flash partition table**
  when a capture contains a `bdinfo` or `mtdparts` dump. The partition rows carry
  the `mask_flags` read-only marker, which is the operationally interesting
  column: it says which partitions an operator at that prompt can rewrite.

  Both were dead code on the engine side and the port started by measuring that,
  not by assuming it. Across all 31 public corpus logs they produced nothing,
  while two of those logs contain a full bdinfo dump. The cause was a command
  gate: the blocks were only parsed once the prompt regex had matched the line
  where the command was typed, and `Boot-> bdinfo` is not U-Boot's default
  prompt. They are now recognised by their own shape.

  The discriminator between board info and an environment variable is the
  whitespace around the `=`: `printenv` emits `baudrate=115200`, `bdinfo` pads to
  a column and emits `baudrate    = 115200 bps`.

  `verdict --json` gained `bdinfo` and `mtd_device` under `uboot_shell`, and a
  top-level `mtd_partitions` array, matching the engine's placement.

## [0.10.0] — 2026-09-28 — the kernel's own hardening report

`bootintel verdict` now answers for captures that never reach a U-Boot prompt.
A plain boot log states which protections the kernel enforces, and reporting
"nothing was assessed" about one of those was false.

### Added
- **`bootintel verdict` now reports the kernel hardening posture** alongside the
  boot chain: mandatory access control, memory initialisation, and kernel address
  randomisation, read from what the kernel itself announced at boot. Ported from
  the engine and pinned against it by three new kernel-stage fixtures in the
  shared expectation.

  It keeps the distinction that decides whether the output is trustworthy:
  `selinux=0` on a command line means SELinux was switched off, while `selinux=0`
  under `Unknown command line parameters:` means the kernel ignored it and SELinux
  is not compiled in at all. A different, worse fact. Likewise `capability` in the
  LSM list is not access control, so `lsm=capability,integrity` is reported as
  having no MAC while `lsm=capability,yama,apparmor` is not.

  Absence is never evidence: a capture that does not mention KASLR is not a
  capture proving it off, and nothing is reported on that basis.

### Changed
- **`verdict` exits 3 only when a capture yields neither a U-Boot session nor a
  hardening posture.** It previously exited 3 whenever there was no session, which
  became wrong once a plain boot log could produce a real answer: "nothing was
  assessed" would have been false, and a CI job keyed on that code would treat an
  answer as a failure to answer. A capture with neither still exits 3.
- `verdict --json` gained an `os_hardening` object, mirroring the engine's key
  names.

## [0.9.0] — 2026-09-28 — the verdict reads the boot output, not just the environment

Both halves of the boot-chain verdict now agree about the same device: the engine and
the CLI reproduce one committed expectation byte for byte, across five fixtures, two
of them real captures rather than synthetic.

### Added
- **`bootintel verdict` now reports what the bootloader actually verified**, not
  only what the environment says it is configured to do. A capture containing
  `Verifying Checksum ... OK` or `Verifying Hash Integrity ... sha256+ OK` no
  longer gets "I cannot tell whether images are checked" while the answer sits in
  the same log. Also reads the i.MX HAB fuse and UBIFS unauthenticated mounts.

  The distinction is kept deliberately: a passing checksum is reported as
  `confirmed`, never `hardened`, and the detail says why. A CRC proves the image
  was not corrupt; anyone who can write the image can recompute it. Only a
  signature (`sha256,rsa2048:dev+ OK`) reports as `hardened`.

  New verdict entry **Secure boot anchor** when the SoC reports `hab fuse not
  enabled`, because while that fuse is unblown the boot ROM runs unsigned images
  whatever the bootloader prints afterwards. It is emitted without needing a
  `printenv`, since the fact does not depend on one.

### Changed
- **Breaking, library only: `boot_chain::assess` returns an `Assessment` struct**
  (`session`, `integrity`, `verdicts`) instead of a `(UbootSession, Vec<Verdict>)`
  tuple, and `boot_chain::verdict` takes the integrity alongside the session. The
  alternative was a second entry point for the same operation, and two functions
  differing only in how much they tell you is worse for whoever reads it next. No
  CLI flag, output or exit code changed.
- `verdict --json` gained a `boot_integrity` object, mirroring the engine's key
  names. Fields are omitted when the capture said nothing about them rather than
  emitted as null.

## [0.8.0] — 2026-09-28 — read the boot chain on the bench, offline

Two halves of one workflow: take the U-Boot prompt on a board in front of you,
and turn the environment you pull off it into a verdict. Both run entirely on
your machine. A consultancy under an NDA cannot upload a client's capture, and
a U-Boot environment is the most sensitive thing in one, so needing a server to
interpret it would have put this out of reach of the people it is for.

### Added
- **`bootintel verdict <capture>`** reads a `printenv` dump taken at the prompt
  and reports what the boot chain permits: whether autoboot is interruptible,
  whether images are verified, whether a netboot path is pre-configured,
  whether `bootargs` can be rewritten, and whether `saveenv` makes any of it
  stick. Text, `--json`, and `--gate-exposed` for CI.

  Every entry names the variable it was read from, because a consultant has to
  defend the answer in a client report rather than quote a tool. Absence is
  reported as `unknown`, never as `hardened`: U-Boot prints only what is set, so
  a missing `bootdelay` means the compiled-in default applies and cannot be read
  from a capture.

  Exit codes carry the same discipline: `2` for an empty capture, `3` for
  content with no session in it. "Could not assess" must never look like
  "nothing is wrong", which is the failure mode that makes a CI gate worse than
  no gate.

  `--json` uses the server's key names (`uboot_shell`, `uboot_env`,
  `boot_chain_verdict`) so a consumer can move between this and `scan --api`
  without remapping anything.

- **`bootintel analyze <port> --interrupt-autoboot`** interrupts autoboot on
  connect, takes the prompt, runs the read-only set `printenv`, `bdinfo`,
  `mtdparts`, prints the verdict, and hands the terminal back.

  It hammers the interrupt key from the moment the port opens rather than
  waiting to see a countdown. U-Boot's autoboot delay is a loop around
  `tstc()`, and `bootdelay=0` means that check happens exactly once; by the time
  "Hit any key to stop autoboot" has crossed the wire and been recognised, the
  board has already looked. What catches a one-shot check is the byte already
  sitting in the UART's receive register, so **power-cycle the board after the
  tool says it is hammering**. `--reset-line dtr|rts` pulses a modem line so
  the reset instant is the tool's rather than a human's, on the adapters wired
  for it.

  The hammer never sends CR or LF, and a key containing either is refused:
  hammered bytes accumulate in U-Boot's line buffer, and a newline would
  execute whatever they spell on hardware that is not yours. The default key is
  a space, a bare CR flushes the accumulated bytes before anything is typed,
  and every byte the tool sends is announced so a client transcript shows which
  bytes were the tool's. `--at-prompt` replaces the command set entirely.

  A `#` prompt after the kernel handoff is treated as a Linux shell and
  ignored, because typing `printenv` into a root shell would have produced a
  confident, wrong verdict. A prompt that does not answer re-arms rather than
  abandoning the attempt. A window that is never caught is reported, with the
  four things worth checking, rather than exiting quietly.

  Not wired into `--tui`; that combination is refused rather than silently
  ignored.

### Changed
- The verdict rules now exist in two places, here and in the bootintel.com
  engine, which is the drift problem the cross-implementation detector parity
  work fixed. Neither side is the reference:
  `crates/detectors/tests/fixtures/boot_chain/expect.txt` is, and the engine
  repo holds a byte-identical copy that its own test asserts against. Two of
  the three fixtures are real boards whose vendor prompt (`RTL8672 #`) the
  engine's stricter pattern skips, so the environment is only provable
  retroactively from the `Environment size:` line: the path a tokeniser rewrite
  breaks silently.

## [0.7.0] — 2026-09-27 — the gate survives a pipe, and history is opt-in

Renumbered from 0.6.1. Making scan history opt in changes a default, and a
user upgrading on a patch would have found `bootintel history` silently
stopped recording. The policy above reserves PATCH for changes with no
user-visible behaviour change, which this is not.

**0.6.1 is withdrawn.** It is the same code as 0.7.0 under a number that
understated it. The GitHub release is retained but no longer marked latest,
and the crates.io version is yanked: a crates.io version can never be reused,
so withdrawing one means publishing a new number, not replacing it.

**Read the second item before upgrading.** It changes a default.

### Fixed
- **`scan --gate-critical` could report success on a capture that trips the
  gate.** Measured on the 0.6.0 release binary, piping into `head` with output
  over the 64 KB pipe buffer: three runs gave exit 1, then 0, then 0, on a log
  with telnet exposed. A CI job piping through `head` or `tee` would go green
  on a device with a critical exposure, non-deterministically, which is the
  worst direction for a gate to fail.

  Cause was ordering. The output write ran before the gate check, so a broken
  pipe propagated up and the handler in main.rs turned it into exit 0 before
  any verdict was evaluated. That handler is right that a reader closing the
  pipe is not an error, but it must not become a verdict. The pipe error is now
  swallowed at the write site only, and the gates decide on findings alone,
  which do not depend on whether anyone was still reading. Any other write
  error is still fatal, and `manpage | head` still exits 0 silently.

### Changed
- **Scan history is now OPT IN. If you relied on it, it has stopped.** Enable
  with `bootintel config set history true` or `BOOTINTEL_HISTORY=1`.

  It was on by default with an opt-out and a one-time notice. That is the wrong
  default for a tool whose pitch is that it uploads nothing: a record of every
  log path a consultant analysed should not appear on disk because nobody said
  no. `bootintel doctor` disclosing it on a fresh machine is what prompted the
  change.

  `no_history` and `BOOTINTEL_NO_HISTORY` still work and still mean off, so
  anyone who had opted out stays opted out. An explicit off beats an explicit
  on, so a machine-wide opt-out cannot be re-enabled by a config file.

- Every "get an API key" message pointed at `bootintel.com/settings/api-keys`,
  a route that has never existed; there is no `/settings` on the site. Keys
  live at `/dashboard/developer`. Six places said otherwise: `doctor`,
  `whoami` twice, `scan --api` twice, `analyze --api`. They now recommend
  `bootintel login` first, which is the path for a person at a terminal and the
  only one that works below Pro.

### Fixed
- **Every "get an API key" message pointed at a URL that 404s.**
  `https://bootintel.com/settings/api-keys` does not exist and never has;
  there is no `/settings` route at all. Keys live at `/dashboard/developer`.
  Six places said otherwise: `doctor`, `whoami` twice, `scan --api` twice, and
  `analyze --api`. Surfaced by running `bootintel doctor` on a Mac, which is
  the first time anyone read that line back.
- The same messages are now correct about what to do, not just where to go.
  `bootintel login` is the path for a person at a terminal and the only one
  that works below Pro, since API-key auth is Pro-gated. They recommend it
  first and mention keys as the CI and scripting option.

## [0.6.0] — 2026-09-27 — applicability without sending the log

New flag, no breaking change, so MINOR per the policy above.

### Added
- **`scan --applicability`** — ask which advisories APPLY without sending the
  boot log. The detectors run locally, exactly as for a plain `scan`, and only
  the component inventory goes up: product names and version strings.

  A consultant cannot upload a client's boot log. That is a contract matter,
  not a preference, and it is the objection that keeps this tool out of the
  segment it fits best. Shipping the curated ruleset down to the client
  instead would hand over the one asset that compounds. So neither travels.

  Hostnames, internal addressing, MACs, serials, keys, kernel command lines
  and partition labels cannot be transmitted by this path structurally, not by
  policy: the payload is built from a fixed map of three detector labels to
  three product names, and every value is re-validated before it leaves.
  Verified against the Android corpus capture, which carries
  `androidboot.serialno=`, `vbmeta.device_state=unlocked` and
  `androidboot.selinux=permissive`, and yields two version strings and nothing
  else.

- **`--dry-run`** alongside it, printing the exact JSON that would be sent and
  exiting without sending. This is how a consultant shows a client what leaves
  the machine, so it is a headline capability rather than a debug switch.

  Needs `bootintel login`; local identification stays free and needs no
  account. Only U-Boot, Linux and BusyBox currently yield a component the
  catalog can match, so those are the only three sent. The other eleven
  detectors are not CVE-tracked products, and inventing entries for them would
  only produce noise.

## [0.5.0] — 2026-09-26 — detector parity, and terminal login

Detector-set parity with the browser detector library at
bootintel.com/tools/fingerprint, which is the source of truth for the
set: it is what the web tool and the legacy Node analyzer both run. This
crate shipped 9 of its 14 detectors and folded two others into the wrong
label, so the same log produced different JSON depending on which
implementation read it.

**This is an output-schema change, which the policy at the top of this
file calls MAJOR.** One finding moves to a different label, one moves out
of a label it never belonged in, and five new labels appear (all three
below), so anything parsing `.findings[]` by label needs a look before
upgrading. The version is deliberately not bumped here —
releasing is handled separately, and the 0.4.0 entry records how this
project numbers a breaking change while pre-1.0.

### Added
- **`bootintel login`** — browser-approved terminal sign-in, replacing
  `export BOOTINTEL_API_KEY=...` by hand. Prints a link with the code
  already in it so the normal path is one click, and prints the code
  separately so you can check it against what the page shows. That
  comparison is the only thing stopping a malicious local process having
  its own login approved, so the wording asks for it rather than just
  offering a button.

  There is a second reason it exists. The server gates `x-api-key` auth at
  the Pro plan, because "API access" there means CI and scripting. Applying
  that to interactive terminal use would have put the applicability lookup,
  the one path usable on a client device under an NDA, out of reach of the
  entry paid tier. The `bic_` token this issues resolves ahead of the
  API-key gate server-side, so programmatic access stays Pro while
  `bootintel login` starts at Researcher.

  Shape is RFC 8628. Token lasts 90 days, is revocable from the account
  page, and is stored via the existing config file so everything that
  already reads `api_key` keeps working. Transient poll failures retry
  quietly and are bounded: a long poll outliving keep-alive is routine, and
  the first live run of this command proved it by surviving a connection
  reset where the only thing that looked wrong was the warning.

- Five detectors, bringing the set to 14 and `bootintel version` to
  `client-side detectors: 14`:
  - **Runtime firmware** — OpenSBI, the RISC-V M-mode runtime.
  - **ROM identifier** — the Espressif mask-ROM build stamp
    (`ESP-ROM:esp32-20160718`), which is what a ROM-level exploit is
    written against.
  - **Firmware SDK** — ESP-IDF version off the 2nd-stage bootloader
    banner. On an ESP target this is the CVE-relevant identifier; the ROM
    stamp rarely moves, the SDK does.
  - **Userland** — BusyBox version. It is printed by 7 of the 31 public
    corpus logs and this crate reported it zero times, so the offline
    story was missing the most common userland component in the category.
  - **Flash layout** — the MTD partition map (15 of the 31 corpus logs
    register one), as `N partitions` plus the named list with sizes. This
    is what a flash-clip read needs in order to know where to read.
- `cargo test -p bootintel --test browser_parity` — runs the browser
  library over all 31 corpus logs (transpiled in-process and evaluated in
  a `vm`, the same way the website repo's own parity test does) and
  asserts the `{label, value, detail}` sequence matches this crate's, log
  for log. Each log is compared twice, as captured and with
  `[12:34:56.123] ` in front of every line, because line-prefix
  normalization is the one place the two could agree on a bare log and
  still disagree on a real capture. It skips loudly when `node` or the website checkout is absent,
  since the crate is published and `cargo test` has to pass for someone
  who only has this repo; `BOOTINTEL_REQUIRE_PARITY=1` turns a skip into
  a failure and `BOOTINTEL_BROWSER_DETECTORS` points at `detectors.ts`.
- Corpus coverage guards: BusyBox must fire on every corpus log that
  prints its banner (7), the partition map on every log that registers
  one (15), and no log may report the same partition twice.

### Changed
- **`OpenSBI x.y` moves from `Bootloader` to `Runtime firmware`.** It is
  the M-mode runtime that hands off to U-Boot, not a bootloader, and the
  browser has always reported it under its own label. Folding it into
  `Bootloader` also *hid* it: on a RISC-V board that prints both (sample
  `bootintel-6.txt`), U-Boot won the precedence chain and the OpenSBI
  version disappeared from CLI output entirely. It is now reported
  alongside the bootloader.
- **An ESP log gains `ROM identifier` and `Firmware SDK` findings.** The
  `Bootloader: Espressif ROM bootloader` finding is unchanged — the ROM
  build stamp and the SDK version are additional labels, not a rename.
- Consumers parsing JSON by label: the two bullets above are the whole
  behaviour change. `Bootloader` for U-Boot / coreboot / GRUB / ESP,
  `Kernel`, `CPU / Arch`, `Init system`, `Device family`, `Network`,
  `Web admin`, `Telnet exposure` and `Autoboot interruptable` keep their
  labels, values and relative order; the five new labels are interleaved
  in the browser's registration order (`Bootloader`, `Runtime firmware`,
  `ROM identifier`, `Firmware SDK`, `Kernel`, `CPU / Arch`, `Userland`,
  `Flash layout`, `Init system`, …) because order is part of what makes
  the two implementations comparable.

### Fixed
- Four divergences from the browser found by the new parity test, each of
  which made the CLI assert something the web tool did not:
  - **Garbled `Kernel` detail.** The build-metadata group was mandatory
    and `\s`-separated, so on a kernel banner that prints no toolchain
    parentheses the match ran across line breaks and swept up unrelated
    text: `bootintel-6.txt` reported a detail of
    `riscv64-unk2OF: fdt: Ignoring memory range 0x40000000 …` and
    `bootintel-17.txt` one of
    `gcc version 4.6.3 (Ti2CPU: ARMv7 Processor [412fc09a] revision 10 …`,
    each stitched out of two different lines. The group is now optional
    and line-bounded, so a banner with no toolchain parentheses yields a
    version and no detail. No log loses its `Kernel` finding.
  - **`CPU / Arch: Xtensa (ESP)` claimed from `esp32` / `esp8266`.**
    Those name a device family, not a CPU, and are reported as such by
    `Device family`. Only the literal arch name counts now.
  - **`Init system: BusyBox init`.** A BusyBox banner says what the
    userland is, not what PID 1 is. The claim is replaced by the new
    `Userland` finding — `bootintel-17.txt` reported
    `Init system: BusyBox init` and now reports
    `Userland: BusyBox 1.20.2`.
  - **`Init system: systemd` inferred from a `Welcome to … Linux`
    greeting.** A distro greeting is not evidence of PID 1;
    `systemd[1]:` is.
- `source` and `line_number` are now derived exactly the way the browser
  derives them — the detector is re-run against each line on its own and
  the first line reproducing the same `value` + `detail` is the evidence.
  The old substring search over the normalized lines could attach a
  `source` for a match that exists on no single line. An aggregate
  finding (`Flash layout`, whose value counts partitions across the whole
  table) correctly carries neither field.
- The two policy detectors (`Telnet exposure`, `Autoboot interruptable`)
  read the original lines rather than the normalized ones, as the browser
  does. Stripping timestamps and ANSI is a presentation choice for the
  inventory detectors; a policy rule should see what the capture
  contained.
- Partition offsets are de-duplicated, so a capture that prints the table
  twice (a reset loop, or two flash devices registering) does not inflate
  the count — `bootintel-9.txt` reports its real 7 partitions rather
  than 14.
- Partition sizes round the way JavaScript's `toFixed` does (ties away
  from zero) rather than the way Rust's formatter does (ties to even).
  Exact ties are common in a partition table: the 1280 KiB `kernel`
  region in `bootintel-12.txt` is `1.3M` in the browser and was `1.2M`
  here.

## [0.4.2] — 2026-09-26 — published as `bootintel`

### Changed
- **The crate is now published as `bootintel`, not `bootintel-cli`.**
  `cargo install bootintel` installs a command called `bootintel`, which
  is what the binary has always been named. The `-cli` suffix made every
  user type one name and get another. crates.io cannot rename a crate, so
  this is a new crate; `bootintel-cli` 0.4.1 is yanked. It had 0 downloads,
  so nothing breaks, and the old name stays reserved under the same account.
  The package directory stays `crates/cli`, since renaming it would churn
  paths for no user-visible gain.
- Numbered 0.4.2 rather than republishing 0.4.1 under the new name: `main`
  was exactly tag `cli-v0.4.1`, so reusing that version would have put a
  crate on crates.io whose contents differed from the tag and the release
  archives. A crates.io version can be yanked but never reused.

## [0.4.1] — 2026-09-26 — publishable to crates.io

No user-visible behaviour change, so PATCH per the policy above.

### Changed
- **The crates can now be published.** `crates/cli` carried
  `publish = false`, present only to satisfy cargo-deny's wildcard-dep
  check because `bootintel-detectors` was declared as a bare path
  dependency. That dependency now carries both a path and a version:
  cargo uses the path for local builds and the version when packaging.
  `cargo deny check` still reports advisories, bans, licenses and
  sources all ok, so the workaround was no longer earning its keep.
- The release workflow gained an opt-in `publish_crates` input and a
  `publish-crates` job. It refuses to start without
  `CARGO_REGISTRY_TOKEN`, because a crates.io version can be yanked but
  never reused, so a half-publish would burn the version permanently.
  The library is published before the binary crate and the job waits for
  index consistency in between, which is not optional: `cargo package -p
  bootintel-cli` fails with `no matching package named
  bootintel-detectors` otherwise.
- Added `docs/releasing.md`, and refreshed four stale `cli-v0.3.1`
  references in the README.

## [0.4.0] — 2026-09-25 — correctness batch: capture loss, CI gates, detector robustness

Numbered 0.4.0 rather than 1.0.0. The policy above calls an exit-code
change MAJOR, and this batch changes one, but the crate is pre-1.0: the
leading zero is the major component, so a breaking change moves the
minor. Releasing 1.0.0 would assert an API-stability commitment this
project has not made. Treat 0.3.x to 0.4.0 as breaking and read the
exit-code note below before upgrading a CI job.

Correctness batch from an SME review that installed the v0.3.1 release
binary and exercised it against socat PTY pairs. Every item below was
reproduced by running, not by reading.

**This batch changes exit-code policy** (see MAJOR in the versioning
policy above): `scan` now exits 2 for an empty/unusable capture and 3
when nothing was recognized, where it previously exited 0 for both.

### Fixed
- **`--log-file` no longer loses the capture.** Bytes were buffered and
  flushed only on `Drop`, so a capture smaller than the 8 KiB buffer —
  which is most of them — reached the filesystem only if the session
  quit through the clean path. Measured on the v0.3.1 binary: the log
  file was 0 bytes at 2, 4, 6, 8 and 10 seconds into a live session and
  0 bytes after both SIGINT and SIGTERM, while the session correctly
  analyzed those same bytes on screen. Writes are now flushed as they
  arrive, which also makes the file `tail -f`-able from another
  terminal. SIGINT/SIGTERM/SIGHUP handlers were added so the terminal
  exits through its normal path — raw mode restored, capture flushed —
  instead of the process dying where it stands.
- **An empty capture no longer passes `--gate-critical` with exit 0.** A
  CI job whose UART never came up, whose adapter fell out, or whose
  artifact path was wrong reported green. `scan` now follows the legacy
  Node analyzer's ladder: 2 for empty or unusable input, 3 for
  non-empty input that matched no detector.
- **Line-anchored detectors no longer die on a line prefix.** A plain
  `U-Boot 2020.10` line was detected, but the same line behind a
  `[12:34:56.789]` prefix, an ISO-8601 timestamp, or an ANSI colour
  escape produced no findings and exit 0. This was self-inflicted:
  `bootintel analyze --log-timestamps` prefixes every line with an
  ISO-8601 timestamp, so the tool's own capture mode broke its own
  `scan`. Lines are now normalized (ANSI CSI stripper + bracketed
  timestamp stripper, ported from the Node analyzer) before matching,
  while evidence still reports the original line verbatim.
- **A non-UTF-8 byte is no longer a hard error.** A capture containing
  `\xff\xfe\x80\x81\xc0\xc1` failed with "stream did not contain valid
  UTF-8" and exit 1, while the Node analyzer read the same file and
  returned findings. That is the normal shape of a real UART capture
  (pre-baud-lock noise, framing errors, a binary splash, a reset
  mid-line) — and since `--log-file` writes raw bytes, `analyze
  --log-file` followed by `scan` could fail on the tool's own output.
  Logs are now read as bytes and decoded lossily; `-v` reports how many
  bytes were replaced. Line numbers are unaffected.
- **A closed pipe is one silent outcome instead of three.** `bootintel
  batch … --format json | head -2` gave exit 1 plus `Error: Broken pipe
  (os error 32)` on 6 of 6 runs when output exceeded the 64 KiB pipe
  buffer, while smaller outputs raced between 141 and 0. `bootintel
  manpage | head` — a packager's first command — hit the same thing.
  The broken-pipe check now walks the whole `anyhow` cause chain and
  understands `serde_json::Error`, which is how the error actually
  arrived, and the result is a silent exit 0 every time.
- **SARIF names the real input file.** Every result carried
  `artifactLocation.uri = "boot.log"` regardless of the input, so the
  SARIF upload action attached findings to a file not in the repository
  and the annotations landed nowhere. The real path is now emitted,
  relative to `$GITHUB_WORKSPACE` (or the working directory) where
  possible, and `stdin` for piped input. `startLine` now comes from the
  detector library rather than a substring search.
- **`-q` quiets, and the upsell is off stdout.** `scan --format text -q`
  still printed a three-line block advertising `--api`, on stdout — so
  `scan --format text > report.txt` shipped marketing inside a
  customer's report, and `-q` did nothing despite its own help text
  promising it suppresses banners and status hints. The summary block
  now goes to stderr and honours `-q`; stdout carries findings only.
- **`bootintel cve` works when installed.** It resolved
  `./data/embedded-cves-feed.json` relative to the working directory, so
  it only ever worked from inside a source checkout. The feed is now
  read from the platform state dir, populated by a new `--refresh` that
  fetches the public feed. Repo-relative paths are still tried last.
- **`bootintel analyze /etc/hostname` is diagnosed correctly.** A
  readable regular file reported "permission denied" and advised adding
  the user to the `dialout` group. It now says the path is not a serial
  device and points at `scan` / `watch`.
- **The non-TTY error has a recovery hint.** `entering terminal raw
  mode: No such device or address` was the only error in the CLI that
  arrived with no suggested next step.

### Changed
- `bootintel ports` sorts USB adapters first and annotates them with the
  manufacturer/product string. Previously 32 bare `/dev/ttyS*` paths
  came back in enumeration order with nothing to distinguish the one
  adapter the user was looking for.
- `bootintel scan`'s local history write is disclosed on first use — one
  stderr notice naming the file, what it records, and how to turn it
  off. It remains on by default and entirely local; it was simply never
  announced, which sits badly with a tool whose pitch is that it uploads
  nothing.

### Added
- `analysis_status` (`matched` / `unrecognized`) on the `scan --format
  json` envelope, and `line_number` on each finding. Both are additive;
  no existing key changed name or meaning. `bootintel schema` and the
  bundled GitHub Action are updated to match.
- Signed build-provenance attestations
  (`actions/attest-build-provenance`) for every release artifact and for
  the container image. Free for public repositories, keyless, and a
  stronger claim than a paid signing certificate — it binds an artifact
  to the workflow and commit that built it. `SHA256SUMS` is unchanged.
- Regression tests for each of the above, including four that assert the
  log file is non-zero **mid-session** (the pre-existing
  flush-on-drop test passed against the broken code).

## [0.3.1] — 2026-08-30 — security-hygiene + refactor + dep bumps

Patch release. No user-facing feature changes — this is the pre-public-flip cleanup batch identified by the SME review of 0.3.0. Every 0.3.0 workflow keeps working with identical semantics; the code is smaller, safer, and easier to review.

### Security
- Config file (`~/.config/bootintel/config.toml` and platform equivalents) is now created + written with mode 0600 on Unix, and its parent dir with 0700. Prior to this change the file inherited the process umask (typically 0644), leaving the plaintext `api_key` field readable by any local account. Windows inherits its user-only ACL from `%APPDATA%\bootintel\` — verified + documented.
- History file (`~/.local/state/bootintel/history.jsonl` and platform equivalents) opens with an explicit `.mode(0o600)` + `O_CLOEXEC` on Unix (owner-only from creation, no race window between `open(create)` and a later chmod). Parent dir also 0700. Protects the scanned-path list from local snooping.
- `bootintel config set api_key bik_...` now masks the api_key value on its stderr echo (`...abcd` instead of the full key). The value still lives in `argv` / shell history — an interactive-prompt path (rpassword-style) is a follow-up feature.

### Fixed
- `bootintel whoami` no longer stuffs the 429 retry-after seconds into the `tier` display field with an in-code comment that self-flagged the hijack as a "hack". Added a typed `Identity::rate_limited: Option<u64>` field; text output emits `retry: Ns`, JSON emits `rate_limited_retry_secs`. Also deleted a `let client = ScanClient::new(...); let _ = client;` dead binding in the same function whose two comments contradicted each other about whether the client was in use.
- Detector-tests comment/assertion contradiction: `sample_matches_expected_9_labels` said "trip every detector except… actually all 9 fire" while the assertion listed 8 labels. Renamed to `sample_matches_expected_8_labels` with a comment matching reality (Telnet isn't in SAMPLE and is negative-tested separately).
- README + `.github/actions/bootintel-scan/action.yml` GH-Action pin examples bumped from `cli-v0.2.0` / `cli-v0.1.0` to `cli-v0.3.0` (they'd gone stale after the 0.3.0 tag shipped).
- `SECURITY.md` supported-versions table refreshed for 0.3.x: `0.3.x` is now the actively-supported line, `0.2.x` drops to "critical fixes only until 2026-11-30", and the "Once 0.3.x ships…" future-tense paragraph is replaced with the concrete end date.
- `cargo doc --features tui --no-deps` now exits clean, zero warnings. Fixed 26 rustdoc warnings: bare URLs → `<angle-brackets>`, 20 unclosed `<prefix>` HTML-lookalike tags in `term::hotkey::Action` doc comments → backticked \`prefix\`, unclosed `<port>` tag in `term/mod.rs`, unresolved `[bootintel]` intra-doc link in `analyze.rs`.
- `cargo audit`: 0 advisories (was 2 open unsoundness advisories in `lru 0.12.5`, pulled transitively by `ratatui 0.29`). Cleared by the ratatui 0.30 → lru 0.18.3 bump.

### Changed
- Extracted `output::resolve_color_mode(no_color_flag, stream)` (and the pure-decision variant `resolve_color_mode_from_tty(no_color_flag, is_tty)`). Was duplicated across 6 subcommands (`scan`, `batch`, `diff`, `watch`, `init`, `cve`, `demo`, `view`) with slight variations — some checked `.is_empty()`, some used `is_none_or`, `watch` returned bare `bool` instead of `ColorMode`. Single implementation now.
- Extracted `crate::config::resolve_api_base(cli_flag)` + `crate::config::resolve_api_key()` + `crate::api::endpoints::require_safe_transport(base, sending_credential)`. Deletes the 40-line CLI-flag > env > config > default resolution + plaintext-transport branch that was duplicated across `scan`, `analyze`, and `whoami`.
- Unified `mask_secret` (config.rs) and `last4` (whoami.rs) into `crate::output::mask_tail(s, keep)` — one UTF-8-safe `char_indices()`-based implementation instead of two `.chars().rev().take(N).collect::<Vec<_>>().into_iter().rev()` double-reverse-with-alloc idioms.
- Replaced stringly-typed config-key dispatch with `enum ConfigKey { ApiBase, ApiKey, DefaultFormat, NoHistory }` + `impl { as_str, from_str }` + `pub const ALL_KEYS`. Adding a fifth key is now one enum variant + one arm each in `get_effective`, `apply`, and `from_str` — all in `config.rs`, no cross-file edits. Match exhaustiveness means the compiler yells if a new variant is missed.
- Added `deny.toml` at the repo root. Enforces: SPDX license allowlist (Apache-2.0 / MIT / BSD-2/3 / ISC / Unicode-3.0 / 0BSD / BSL-1.0 / Unlicense / MPL-2.0 / Zlib / CDLA-Permissive-2.0 / Apache-2.0 WITH LLVM-exception); crates.io-only source; wildcard-deny with an explicit workspace-path allow; duplicate-crate skiplist for the legitimately-multi-versioned syn/hashbrown/thiserror/windows-* branches. Wired into CI's existing `audit` job as `cargo deny check` — blocking on failure.
- Split `crates/cli/src/cmd/scan.rs` (699 LOC, five concerns) into `scan/{mod,api,baseline,context}.rs` (max 279 LOC). Preserved via `git mv` so `git log --follow` still tracks the old file. Import path from `main.rs` unchanged.
- Renamed `cmd::term::run_cmd` → `run` and `cmd::analyze::run_cmd` → `run` (every other cmd module already exported `pub fn run`); renamed the lower-level session-entry functions `term::run::run` → `run_session` and `tui::run::run` → `run_session` (removes the module-vs-function name clash).
- `Config::no_history: Option<bool>` → `bool` with `#[serde(default)]`. A boolean has no meaningful "unset" state, and the 3-arm `Some(true) / Some(false) / None` match in `effective_no_history` collapses to 2.
- Miscellaneous readability: mid-file `use crate::output::html_escape as html_esc` imports in `batch.rs` / `cve.rs` / `diff.rs` moved to top-of-file (alias dropped, callsites use `html_escape` directly); `history::run_json`'s 8KB manual read/write loop replaced with `std::io::copy`; `history::display_shorten` uses `dirs::home_dir()` instead of `$HOME` env var (works on Windows now).
- Every env-touching test now grabs a single process-wide `crate::test_util::env_lock()` mutex. Pre-fix, `config.rs` had its own private lock and every other module raced. Prevents intermittent parallel-test failures on busy CI runners.

### Dependencies
- `ratatui` 0.29 → 0.30 (cascade: upgraded transitive `lru` from 0.12.5 to 0.18.3, clearing 2 open unsoundness advisories).
- `crossterm` 0.28 → 0.29 (matched to ratatui 0.30's expected crossterm major).
- `dirs` 5 → 6.
- `clap_mangen` 0.2 → 0.3.
- `serialport` 4.9 → 4.10.
- `clap` `env` feature enabled explicitly (became stricter in the clap 4.5 → 4.6 range picked up transitively by the above).
- Added `libc` as a Unix-only direct dep (was already transitive) for `O_CLOEXEC` on the history file.

## [0.3.0] — 2026-08-29 — config file + Windows installer + whoami + history

Follow-up release adding four opt-in UX conveniences requested by early users. No breaking changes; every 0.2.0 workflow keeps working. All new features are additive.

### Added — per-user config file (`bootintel config`)
- New TOML config file at the platform-native XDG-shaped path (`$XDG_CONFIG_HOME/bootintel/config.toml` on Linux, `~/Library/Application Support/bootintel/config.toml` on macOS, `%APPDATA%\bootintel\config.toml` on Windows).
- Supported keys: `api_base`, `api_key`, `default_format`, `no_history`.
- Precedence: CLI flag > env var > config file > built-in default. Standard order — matches git config, aws-cli, ripgrep.
- New subcommand `bootintel config path | list | get | set | edit`. `set` writes atomically (`.tmp` + rename), refuses to write through symlinks, and `edit` picks `$EDITOR` → `$VISUAL` → nano / vi / notepad. `list` masks `api_key` to just the last 4 chars.
- Config reads are graceful-degrade: a missing / unreadable / malformed file resolves to defaults with a `-vv` debug line, never bails.

### Added — Windows PowerShell installer
- New `packaging/scripts/install.ps1` mirroring `install.sh` feature-for-feature. One-liner: `iwr -useb https://raw.githubusercontent.com/bootintel/cli/main/packaging/scripts/install.ps1 | iex`.
- Detects arch (AMD64 supported; ARM64 errors with a `cargo install` hint), resolves latest version from the GH API (or `$env:BOOTINTEL_VERSION`), downloads + SHA256-verifies the .zip, extracts `bootintel.exe` to `$env:USERPROFILE\.local\bin` (overridable via `$env:BOOTINTEL_INSTALL_DIR`), and prints a `setx PATH` line when the dir isn't on PATH.
- Idempotent (refuses to overwrite unless `-Force` / `$env:BOOTINTEL_FORCE=1`). Supports offline installs via `$env:BOOTINTEL_TARBALL` (same env-var shape as install.sh). `-WhatIf` dry-runs the install step.
- Syntax-verified against PowerShell 7.6 with `[System.Management.Automation.Language.Parser]::ParseFile`.

### Added — `bootintel whoami`
- Verify the current API key without running a scan (previously users had to `bootintel scan foo.log --api` to check auth, which posted the whole log).
- Two-stage discovery: tries `GET /api/whoami` first, falls back to a minimal 1-byte authed `/api/analysis/scan` if the /whoami endpoint isn't shipped.
- Prints identity: api base + masked key + status + email + tier + today's quota. `--json` for machine-readable output. Missing fields render as `unknown` / `null` (never fabricated).
- Sysexits-style exit codes for CI dispatch: 0 authenticated, 65 EX_DATAERR, 69 EX_UNAVAILABLE, 77 EX_NOPERM. Respects the plaintext-transport guard (refuses to send the key over `http://` unless loopback).

### Added — `bootintel history`
- Append-only JSONL log of every `bootintel scan` / `bootintel analyze` invocation. Storage at `$XDG_STATE_HOME/bootintel/history.jsonl` (Linux; macOS + Windows use `~/Library/Application Support` / `%LOCALAPPDATA%` respectively).
- Entry fields: `ts`, `cmd`, `path`, `format`, `findings`, `critical`, `exit_code`, `cli_version`. Flat shape — jq + grep are both first-class consumers.
- New subcommand `bootintel history`:
  - default → last 20 entries as a text table (newest first)
  - `--limit N` → override the default
  - `--json` → dump raw JSONL to stdout
  - `--path` → print the history file path
  - `--clear` → truncate (prompts for confirmation unless `--yes`; refuses to auto-clear when stdin isn't a TTY)
- Best-effort writes — a locked file / read-only mount / disabled-via-env case never blocks a scan.
- 10 MiB rotation cap (single-generation `.1` sibling) so a CI loop can't silently fill the user's disk.
- Opt-out honors both `BOOTINTEL_NO_HISTORY=1` env and `no_history = true` in the config file. Both surfaced in `bootintel doctor` output.

### Changed
- `bootintel scan --api` and `bootintel analyze --api` now consult the config file for `api_base` / `api_key` after checking env vars, matching the documented precedence chain.
- `bootintel doctor` gained a `scan history` check reporting where writes go (or that they're opted out).
- README's Install section grew the Windows one-liner and documents the `BOOTINTEL_NO_HISTORY` env var.
- Homebrew formula version bumped to `0.3.0` — SHAs are stale until the release cut refreshes them.

## [0.2.0] — 2026-08-26 — first tagged release

The aspirational 0.1.0 CHANGELOG entry below was never tagged. 0.2.0 is the first real ship — everything below plus the additions listed here. If you were pointing at anything called "0.1.0," everything you thought you had is present in 0.2.0.

### Added — new subcommands (15)
- `bootintel batch <dir>` — recurse a directory, one report + a rollup across all files. `--format text|json|csv|html|md`.
- `bootintel diff <before> <after>` — compare two scans' finding sets. `--format text|json|md|html`; exit non-zero on drift.
- `bootintel watch <file>` — tail-and-analyze a growing log; reopens on truncate/rotate.
- `bootintel cve <CVE-ID>` — look up a CVE in the embedded feed (populated every 4h by the cve-alert-bot). `--format text|json|md|html`.
- `bootintel bench <log>` — median + p95 + throughput for the detector pipeline on one log. Cheap perf-regression guard.
- `bootintel replay <log> <port>` — pump a saved log into a serial port with baud-derived pacing. Reproduces customer captures, exercises analyzer streaming.
- `bootintel manpage --out-dir DIR` — emit troff man pages for every subcommand (Homebrew / dpkg / rpm packagers expect this layout).
- `bootintel detectors` — list every registered detector + a one-line description.
- `bootintel schema` — emit JSON Schema (2020-12) for `scan --format json`. Third-party CI can validate + typegen against it.
- `bootintel encode-share <log>` / `bootintel decode-share <URL>` — stdout-only round-trip for the fingerprint URL compressor. Composes cleanly in shell.
- `bootintel export <log> <out>` — bundle log + findings + tool metadata into one JSON for support tickets. No PII collected.
- `bootintel view <bundle-or-json>` — re-render an archived JSON in any output format. Handy when the log is gone.
- `bootintel demo` — run scan on the built-in SAMPLE log. Zero-arg "show me what this does."
- `bootintel init` — bootstrap the per-user config dir with a macros stub + shell-completion install hints.
- `bootintel doctor` — sanity-check the environment: serial devices, dialout group, `$TERM`, tmux/screen prefix collision, `$BOOTINTEL_API_*`. Exit 0 if all-required checks pass.
- `bootintel completions <shell>` — bash / zsh / fish / powershell / elvish completion scripts. `powershell` + `pwsh` both accepted as aliases (kebab-case default was a UX regression).

### Added — new output formats
- `--format html` (scan / batch / diff / cve / view) — self-contained single-page report, inlined CSS, no JS, no external fonts. Portable "share with the vendor" artifact.
- `--format csv` (scan / batch) — RFC 4180, header + one row per finding. Pandas + spreadsheet consumers.
- `--format md` (scan / batch) — GitHub-flavored markdown with the critical-exposure callout + table + version footer. Meant for GITHUB_STEP_SUMMARY, PR bodies, Slack. Aliased as `markdown`.

### Added — scan flags
- `--only LIST` / `--skip LIST` — filter detectors by comma-separated label list, applied together.
- `--gate 'EXPR'` (repeatable) — assert properties of the finding set with a small DSL: `Label`, `!Label`, `Label=value`, `Label~=regex`. Exit 1 on any failed assertion.
- `--baseline PATH.json` — diff against a saved baseline; exit 1 on drift. The CI regression pattern: check the baseline into the repo, run on PRs.
- `--context N` — show N chars of surrounding log per finding (`grep -C`-shape). Only affects `--format text`.
- `-v` / `-vv` / `--verbose` — global verbose stderr with `[v]` / `[vv]` prefix; never contaminates stdout.
- `-q` / `--quiet` — suppress banners + status hints. Errors still fire on stderr.
- `--no-color` (plus `NO_COLOR` env respect + TTY detection) — deterministic no-ANSI output for pipes / CI.

### Added — --tui hotkey parity (finish-work for 5 stubs)
- `Ctrl-A x` — hex display mode (raw-byte ring, hexdump -C layout, offsets stay absolute as the ring wraps).
- `Ctrl-A p` — paste file (bottom-line input modal → 20ms/line paced write with the current TX-newline transform).
- `Ctrl-A a` — change baud (same modal → `set_baud_rate` in place; hangup + reopen preserve the new baud).
- `Ctrl-A h` — hangup (reader-thread bounce: signal shutdown, drop port, sleep 500ms, reopen, spawn fresh reader; fd churn only, analyzer state preserved).
- `Ctrl-A m` — RX newline mapping (None / CrToLf / StripCr; applied before feed_bytes so pane + analyzer both see the normalized stream).

### Added — minicom / picocom feature parity
- `Ctrl-A b` — BREAK signal (250ms).
- `Ctrl-A d` / `Ctrl-A r` — toggle DTR / RTS (tracks state so a toggle is idempotent).
- `Ctrl-A i` — port + baud + modem-control + newline-mode info line.
- `Ctrl-A t` — session-relative timestamp toggle on inline RX display.
- `Ctrl-A e` — local echo toggle (plain-term only; no-op in --tui with a status note).
- `Ctrl-A n` — cycle TX newline mode: Passthrough / LF / CR / CRLF.
- F1–F12 macros — configurable via `$XDG_CONFIG_HOME/bootintel/macros.toml` (or overridable per-run with `--macros`). Sent through the current TX newline transform.
- `--escape ctrl-t` (or any Ctrl+letter) — remap the hotkey prefix when Ctrl-A collides with tmux/screen. Auto-detects `$TMUX` / `$STY` and prints a hint if the default would be intercepted. All hotkey help strings + the TUI status bar spell the active prefix.
- `--backspace del` / `--backspace bs` — encode Backspace as either DEL (0x7f, minicom default) or BS (0x08, some legacy consoles).

### Added — dashboard + config
- `bootintel init --config-dir DIR` honors the explicit dir verbatim (previously wrongly took `.parent()` on it, treating an explicit user input as a file path).
- `bootintel version --json` — machine-readable version, target, features, detector list.

### Fixed since 0.1.0
- **Serial errors are now actionable**: permission-denied on `/dev/ttyUSB0` prints the `dialout`-group remediation on Linux and Full Disk Access hint on macOS. `AddrInUse` / `ResourceBusy` points at `lsof` / `fuser`. Not-found points at `bootintel ports`.
- **Serial exclusive lock (`TIOCEXCL`)** on Unix so concurrent `bootintel term` / picocom / screen sessions on the same port can't silently corrupt each other's stream.
- **`--log-file` refuses to overwrite by default**. Existing behavior (silent overwrite) was a captured-boot-session destroyer. Opt in via `--log-append` or `--log-overwrite` explicitly.
- **429 rate-limit wording no longer hardcodes tier names or prices**; points at `bootintel.com/pricing` neutrally so tier renames don't require a CLI release.
- **ANSI-escape sanitization** on all rendered detector fields (label / value / detail / CVE) across `analyze` inline output, `--tui`, `scan --format text`, and `scan --api` output. Prevents a hostile boot log from smuggling terminal-injection sequences through the render path.
- **`path.exists()` TOCTOU removed** from `scan` and `share`: permission-denied on the input file no longer misreports as "not found."
- **`ureq` TLS features locked in explicitly** (`default-features = false, features = ["json", "tls", "gzip"]`) so a future refactor can't accidentally strip HTTPS by adding `default-features = false` for a different reason.
- **PowerShell completion accepts `powershell` + `pwsh`** — clap's default kebab-case rendering was `power-shell`, which no user types.
- **--api retry with jittered exponential backoff** — 5xx no longer fails on the first hop; retries 4×, then surfaces a real error.

### Added — distribution infrastructure
- `.github/workflows/cli-release.yml` — 5-platform release workflow (linux/macos/windows × x86_64/aarch64), workflow_dispatch only, produces a GH Release draft. Optional `publish_docker` input for the multi-arch image.
- `Dockerfile` — multi-stage build (rust:1.90-bookworm → distroless-cc, final ~42 MiB). Publishes to `ghcr.io/zenofex/bootintel`.
- `packaging/scripts/install.sh` — POSIX shell installer (`curl … | sh`) that detects OS/arch, downloads from GH Releases, verifies SHA256. `BOOTINTEL_TARBALL=…` env for offline / air-gapped install.
- `flake.nix` — reproducible Nix build (`nix build .`, `nix run .#`).
- `packaging/homebrew/bootintel.rb` — Homebrew formula (SHA256 values populated post-release from the workflow's SHA256SUMS artifact).
- `.github/actions/bootintel-scan/action.yml` — reusable GH Action wrapping the native binary via install.sh.

### Fixed — Docker builder Rust bump
- Pinned to `rust:1.90-bookworm` (was 1.83, but transitive deps via ratatui + darling required 1.88+).

## [0.1.0] — 2026-08-21 — pre-tag scaffolding (never released)

Initial release. All six subcommands live; five branch-based milestones (M1-M5) shipped over 2026-08-19 → 2026-08-21.

### Added

- `bootintel scan <file>` — analyze a saved boot log. `--format json|text|sarif|junit`, `--gate-critical`, stdin via `-`. Nine detectors: Bootloader, Kernel, Model, CPU, Family, Init, Web, Network, Autoboot interruptable / Telnet exposure (critical).
- `bootintel scan --api` / `--api --preview` — POST log to bootintel.com for full CVE matching + exploit paths + (paid tiers) AI summary. Sysexits-style exit codes for CI dispatch (75 rate-limited, 77 unauthorized, 76 protocol, 69 network, 65 bad-request).
- `bootintel share <file>` — print bootintel.com URL with log embedded via lz-string. No upload.
- `bootintel ports` — list serial ports on this machine with USB VID/PID + product info.
- `bootintel version` — version, detector count, build metadata.
- `bootintel term <port>` — interactive picocom-shaped UART terminal. Baud/data-bits/parity/stop-bits/flow-control. `--log-file` captures raw bytes in parallel. Ctrl-A q to quit, Ctrl-A ? for help.
- `bootintel analyze <port>` — term + streaming client-side detector analysis. Findings surface as inline `[bootintel] ●` lines. Ctrl-A hotkeys: `l` toggle live display, `c` clear+re-scan, `s` save findings JSON, `u` copy share URL, `f` full server-side analysis (M4).
- `bootintel analyze --tui` — split-screen ratatui dashboard alternative to inline output. PgUp/PgDn/Home/End scroll the serial pane. Feature-flagged (`--features tui`).

### Compatibility

- JSON output envelope: `{bootintel_version, analysis_source, detector_count, findings}`. Downstream consumers reading `.findings[]` can rely on the array shape across releases.
- Response schema from `--api` is graceful-degrade: unknown server fields are preserved via a passthrough `extra` map, so a server-side schema addition never crashes an older CLI.

### Not yet in 0.1.0

- Auto-update (`bootintel update`) — deliberately skipped for supply-chain reasons. Distribution via package managers is the update mechanism.
- Telemetry — off by default. Opt-in path not yet wired.
- PDF report download subcommand — server-side endpoint exists but no client-side wrapper yet.
- Windows support — the Rust code compiles for Windows and the release workflow builds it, but install.sh doesn't handle Windows yet (`.ps1` installer is a follow-up).

[Unreleased]: https://github.com/bootintel/cli/compare/cli-v0.13.0...HEAD
[0.13.0]: https://github.com/bootintel/cli/releases/tag/cli-v0.13.0
[0.12.0]: https://github.com/bootintel/cli/releases/tag/cli-v0.12.0
[0.11.0]: https://github.com/bootintel/cli/releases/tag/cli-v0.11.0
[0.10.0]: https://github.com/bootintel/cli/releases/tag/cli-v0.10.0
[0.9.0]: https://github.com/bootintel/cli/releases/tag/cli-v0.9.0
[0.8.0]: https://github.com/bootintel/cli/releases/tag/cli-v0.8.0
[0.7.0]: https://github.com/bootintel/cli/releases/tag/cli-v0.7.0
[0.6.1]: https://github.com/bootintel/cli/releases/tag/cli-v0.6.1
[0.6.0]: https://github.com/bootintel/cli/releases/tag/cli-v0.6.0
[0.5.0]: https://github.com/bootintel/cli/releases/tag/cli-v0.5.0
[0.4.2]: https://github.com/bootintel/cli/releases/tag/cli-v0.4.2
[0.4.1]: https://github.com/bootintel/cli/releases/tag/cli-v0.4.1
[0.4.0]: https://github.com/bootintel/cli/releases/tag/cli-v0.4.0
[0.3.1]: https://github.com/bootintel/cli/releases/tag/cli-v0.3.1
[0.3.0]: https://github.com/bootintel/cli/releases/tag/cli-v0.3.0
[0.2.0]: https://github.com/bootintel/cli/releases/tag/cli-v0.2.0
[0.1.0]: https://github.com/bootintel/cli/blob/cli-v0.2.0/CHANGELOG.md#010--2026-08-21--pre-tag-scaffolding-never-released
