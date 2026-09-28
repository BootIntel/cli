//! Kernel hardening posture, and the two lines that mean opposite things.
//!
//! The rules are pinned against the engine by the shared expectation in
//! `tests/fixtures/boot_chain/expect.txt`, which now carries three kernel-stage
//! fixtures. These cover the cases where a careless implementation says
//! something false.

use bootintel_detectors::os_hardening::parse;

/// `selinux=0` means SELinux was switched off when it appears on a command
/// line, and means SELinux is not compiled in at all when it appears under
/// `Unknown command line parameters:`, because that line is the kernel saying it
/// ignored the parameter. The second is a different and worse fact, and
/// reporting it as the first would describe a device that does not exist.
#[test]
fn an_ignored_selinux_parameter_is_not_a_disabled_one() {
    let ignored =
        parse("[    0.000000] Unknown command line parameters: stmmaceth=chain_mode:1 selinux=0\n");
    assert_eq!(ignored.selinux.as_deref(), Some("not_supported"));
    assert_eq!(
        ignored.ignored_kernel_parameters.as_deref(),
        Some("stmmaceth=chain_mode:1 selinux=0")
    );

    let disabled =
        parse("cmdline: console=ttyS3 earlyprintk clk_ignore_unused selinux=0 scandelay root=/2\n");
    assert_eq!(disabled.selinux.as_deref(), Some("disabled_by_parameter"));
}

/// `capability` is on every kernel and governs privileged operations only. A
/// list containing it and nothing else is a device with no mandatory access
/// control, and a list containing AppArmor is not.
#[test]
fn capability_alone_is_not_mandatory_access_control() {
    let none = parse("[    0.028197] LSM: initializing lsm=capability,integrity\n");
    assert_eq!(none.lsm, ["capability", "integrity"]);
    assert!(none.mac_modules.is_empty());

    let some = parse("[    0.028197] LSM: initializing lsm=capability,yama,apparmor\n");
    assert_eq!(some.mac_modules, ["apparmor"]);
}

/// The same kernel line arrives with a `[    0.000000]` prefix on one device and
/// a syslog prefix on another. Anchoring the pattern silently drops the second.
#[test]
fn a_syslog_prefixed_kernel_line_is_still_read() {
    let h = parse(
        "Feb 25 13:51:14 raspberrypi kernel: mem auto-init: stack:all(zero), heap alloc:off, heap free:off\n",
    );
    let m = h.mem_auto_init.expect("the line was not read");
    assert_eq!(m.stack, "all(zero)");
    assert_eq!(m.heap_alloc, "off");
}

/// The embedded failure mode: the kernel wanted to randomise and the bootloader
/// handed it no entropy, so a device whose vendor believes KASLR is on has it
/// off. The reason is worth keeping, because it names whose bug it is.
#[test]
fn a_missing_kaslr_seed_keeps_its_reason() {
    let h = parse("[    0.379265] KASLR disabled due to lack of seed\n");
    assert_eq!(h.kaslr.as_deref(), Some("disabled"));
    assert_eq!(h.kaslr_reason.as_deref(), Some("lack of seed"));

    let on = parse("[    0.000000] KASLR enabled\n");
    assert_eq!(on.kaslr.as_deref(), Some("enabled"));
    assert_eq!(on.kaslr_reason, None);
}

/// A capture that never mentions KASLR is not a capture proving it off.
/// Reporting hardening as absent because the log is quiet is the same error as
/// inventing an environment out of a kernel command line.
#[test]
fn a_quiet_log_claims_nothing() {
    let h = parse(
        "U-Boot 2020.10 (Sep 17 2023)\n[    0.000000] Linux version 5.10.0\n\
         [    1.000000] procd: - init -\n",
    );
    assert!(h.is_empty(), "invented a posture: {h:?}");
}

/// First observation wins, so a later line cannot overwrite the evidence that
/// justified the original reading. Mirrors the engine's `setdefault`.
#[test]
fn the_first_reading_of_each_fact_is_kept() {
    let h =
        parse("[    0.000000] KASLR enabled\n[    9.000000] KASLR disabled due to lack of seed\n");
    assert_eq!(h.kaslr.as_deref(), Some("enabled"));
    assert_eq!(h.kaslr_reason, None);
}
