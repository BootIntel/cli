//! `analyze --interrupt-autoboot` argument handling, driven as a process.
//!
//! The state machine and the timing claim are unit-tested in
//! `src/term/autoboot.rs`, including against a simulated board whose autoboot
//! check runs exactly once. What only the binary can show is that the refusals
//! happen BEFORE a port is opened and a board is touched: a consultant finds
//! out that `--interrupt-key` needs `--interrupt-autoboot` while they are still
//! typing, not after the one window on a client's device has gone.

use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_bootintel");

/// A port that does not exist. Every case here must fail on the arguments
/// before the port is ever opened, so no hardware is implied.
const PORT: &str = "/dev/ttyUSB-bootintel-does-not-exist";

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env("BOOTINTEL_NO_HISTORY", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("running bootintel")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The safety rail. The key is sent repeatedly and its bytes accumulate in
/// U-Boot's line buffer, so a CR would execute whatever they spell on hardware
/// that is not ours.
#[test]
fn a_carriage_return_interrupt_key_is_refused_before_the_port_opens() {
    for spec in ["0x0d", "0x0a"] {
        let out = run(&[
            "analyze",
            PORT,
            "--interrupt-autoboot",
            "--interrupt-key",
            spec,
        ]);
        assert!(!out.status.success(), "{spec} was accepted");
        let err = stderr(&out);
        assert!(err.contains("CR or LF"), "{spec}: {err}");
        // Proof it never got as far as the hardware.
        assert!(
            !err.contains("No such file") && !err.contains("no such"),
            "{spec} reached the port before being refused: {err}"
        );
    }
}

/// Silently ignoring these would be worse than refusing them: someone who
/// passed `--interrupt-key esc` and got a plain terminal would reasonably
/// conclude the tool tried and the board refused.
#[test]
fn tuning_flags_without_the_feature_flag_are_refused() {
    for args in [
        vec!["--interrupt-key", "esc"],
        vec!["--interrupt-timeout", "10"],
        vec!["--at-prompt", "printenv"],
        vec!["--reset-line", "dtr"],
    ] {
        let mut full = vec!["analyze", PORT];
        full.extend(args.iter().copied());
        let out = run(&full);
        assert!(!out.status.success(), "{args:?} was accepted");
        let err = stderr(&out);
        assert!(err.contains("--interrupt-autoboot"), "{args:?}: {err}");
    }
}

#[test]
fn nonsense_tuning_values_are_refused() {
    let cases: &[(&[&str], &str)] = &[
        (&["--interrupt-interval", "0"], "at least 1ms"),
        (&["--interrupt-timeout", "0"], "at least 1s"),
        (&["--at-prompt", "  "], "cannot be empty"),
        (&["--interrupt-key", "0xZZ"], "hex"),
    ];
    for (args, expected) in cases {
        let mut full = vec!["analyze", PORT, "--interrupt-autoboot"];
        full.extend(args.iter().copied());
        let out = run(&full);
        assert!(!out.status.success(), "{args:?} was accepted");
        assert!(
            stderr(&out).contains(expected),
            "{args:?}: {}",
            stderr(&out)
        );
    }
}

/// The help text is where an operator learns the one thing they have to do
/// (power-cycle) and the one thing that can bite them (a key that ends a line).
#[test]
fn the_help_says_what_the_operator_has_to_do() {
    let out = run(&["analyze", "--help"]);
    let text = String::from_utf8_lossy(&out.stdout);
    for expected in [
        "POWER-CYCLE",
        "bootdelay=0",
        "read-only",
        "CR and LF are refused",
    ] {
        assert!(text.contains(expected), "missing {expected:?} from --help");
    }
}

/// A valid invocation must get past argument handling and fail on the missing
/// port instead, which is what proves the refusals above are about the
/// arguments and not about the port.
#[test]
fn a_valid_invocation_reaches_the_port() {
    let out = run(&[
        "analyze",
        PORT,
        "--interrupt-autoboot",
        "--interrupt-key",
        "esc",
        "--at-prompt",
        "printenv",
    ]);
    assert!(!out.status.success());
    let err = stderr(&out).to_lowercase();
    assert!(
        err.contains("port") || err.contains("no such") || err.contains("not found"),
        "expected a port error, got: {}",
        stderr(&out)
    );
}
