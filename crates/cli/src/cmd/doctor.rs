//! `bootintel doctor` — sanity-check the environment.
//!
//! Runs a handful of first-run checks so a new user can figure out
//! *why* `bootintel term /dev/ttyUSB0` doesn't work without needing
//! to read forum threads. Each check is a `Check` — one line per
//! result: OK / WARN / FAIL, one liner explaining what to do.
//!
//! Exit code is 0 on all-OK / any WARN, 1 if any FAIL. WARN means
//! "probably fine, but worth noting"; FAIL means "you almost
//! certainly can't use bootintel yet, here's the fix."

use anyhow::Result;
use clap::Args as ClapArgs;
use serialport::available_ports;

#[derive(ClapArgs, Debug)]
pub struct Args {}

enum Status {
    Ok,
    Warn,
    Fail,
}

struct Check {
    name: &'static str,
    status: Status,
    detail: String,
}

pub fn run(_args: Args) -> Result<()> {
    let checks = vec![
        check_bootintel_version(),
        check_serial_ports(),
        #[cfg(target_os = "linux")]
        check_dialout_group(),
        check_terminal_env(),
        check_tmux_screen(),
        check_api_base(),
        check_api_key(),
        check_history(),
    ];

    for c in &checks {
        print_check(c);
    }

    let any_fail = checks.iter().any(|c| matches!(c.status, Status::Fail));
    println!();
    if any_fail {
        println!(
            "bootintel doctor: {} FAIL — see above.",
            checks
                .iter()
                .filter(|c| matches!(c.status, Status::Fail))
                .count()
        );
        std::process::exit(1);
    }
    let warn_count = checks
        .iter()
        .filter(|c| matches!(c.status, Status::Warn))
        .count();
    if warn_count > 0 {
        println!("bootintel doctor: all-required OK ({warn_count} warning(s) — see above).");
    } else {
        println!("bootintel doctor: all checks passed.");
    }
    Ok(())
}

fn print_check(c: &Check) {
    let (mark, tag) = match c.status {
        Status::Ok => ("✓", "OK  "),
        Status::Warn => ("!", "WARN"),
        Status::Fail => ("✗", "FAIL"),
    };
    println!("  {mark} {tag}  {}", c.name);
    for line in c.detail.lines() {
        println!("           {line}");
    }
}

fn check_bootintel_version() -> Check {
    Check {
        name: "bootintel build",
        status: Status::Ok,
        detail: format!(
            "v{} ({} {})",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH,
        ),
    }
}

fn check_serial_ports() -> Check {
    match available_ports() {
        Ok(ports) if ports.is_empty() => Check {
            name: "serial ports",
            status: Status::Warn,
            detail: "no serial devices detected. Plug in a USB-serial adapter and re-run,\nor use socat to create a PTY pair for testing.".into(),
        },
        Ok(ports) => Check {
            name: "serial ports",
            status: Status::Ok,
            detail: ports.iter().take(8).map(|p| p.port_name.clone()).collect::<Vec<_>>().join(", "),
        },
        Err(e) => Check {
            name: "serial ports",
            status: Status::Fail,
            detail: format!("`bootintel ports` errored: {e}"),
        },
    }
}

#[cfg(target_os = "linux")]
fn check_dialout_group() -> Check {
    // /etc/group has `dialout:x:20:user1,user2,...`. We're in it if
    // our username appears there. Skip if we can't identify the user.
    let user = match std::env::var("USER") {
        Ok(u) => u,
        Err(_) => {
            return Check {
                name: "dialout group (Linux)",
                status: Status::Warn,
                detail: "couldn't read $USER; skipping membership check.".into(),
            }
        }
    };
    let group_file = match std::fs::read_to_string("/etc/group") {
        Ok(s) => s,
        Err(e) => {
            return Check {
                name: "dialout group (Linux)",
                status: Status::Warn,
                detail: format!("couldn't read /etc/group: {e}"),
            }
        }
    };
    let in_dialout = group_file
        .lines()
        .filter(|l| l.starts_with("dialout:") || l.starts_with("uucp:"))
        .any(|l| {
            let members = l.split(':').nth(3).unwrap_or("");
            members.split(',').any(|m| m == user)
        });
    if in_dialout {
        Check {
            name: "dialout group (Linux)",
            status: Status::Ok,
            detail: format!("{user} is in dialout (or uucp)."),
        }
    } else {
        Check {
            name: "dialout group (Linux)",
            status: Status::Warn,
            detail: format!(
                "{user} isn't in dialout / uucp. Serial ports may refuse to open.\nFix: sudo usermod -aG dialout {user}  (then log out and back in)"
            ),
        }
    }
}

fn check_terminal_env() -> Check {
    let term = std::env::var("TERM").unwrap_or_default();
    if term.is_empty() {
        Check {
            name: "terminal ($TERM)",
            status: Status::Warn,
            detail: "$TERM is unset. The TUI (`bootintel analyze --tui`) may render weirdly."
                .into(),
        }
    } else if term == "dumb" {
        Check {
            name: "terminal ($TERM)",
            status: Status::Warn,
            detail: "$TERM=dumb — colour + TUI will be disabled.".into(),
        }
    } else {
        Check {
            name: "terminal ($TERM)",
            status: Status::Ok,
            detail: format!("$TERM={term}"),
        }
    }
}

fn check_tmux_screen() -> Check {
    let in_tmux = std::env::var("TMUX").is_ok();
    let in_screen = std::env::var("STY").is_ok();
    if !in_tmux && !in_screen {
        return Check {
            name: "tmux/screen prefix",
            status: Status::Ok,
            detail: "not inside tmux or screen — Ctrl-A hotkey is unclaimed.".into(),
        };
    }
    let host = if in_tmux { "tmux" } else { "screen" };
    Check {
        name: "tmux/screen prefix",
        status: Status::Warn,
        detail: format!(
            "you're inside {host}. If Ctrl-A is your {host} prefix, bootintel hotkeys won't reach it.\nFix: pass --escape ctrl-t (or another Ctrl+letter {host} doesn't use)."
        ),
    }
}

fn check_api_base() -> Check {
    match std::env::var("BOOTINTEL_API_BASE") {
        Ok(v) => Check {
            name: "$BOOTINTEL_API_BASE",
            status: Status::Ok,
            detail: format!(
                "set to {v} (override active — --api hits this instead of bootintel.com)"
            ),
        },
        Err(_) => Check {
            name: "$BOOTINTEL_API_BASE",
            status: Status::Ok,
            detail: "unset — --api defaults to https://bootintel.com".into(),
        },
    }
}

fn check_api_key() -> Check {
    match std::env::var("BOOTINTEL_API_KEY") {
        Ok(v) if !v.is_empty() => Check {
            name: "$BOOTINTEL_API_KEY",
            status: Status::Ok,
            detail: format!("set ({} chars) — --api will use the authenticated endpoint.", v.len()),
        },
        _ => Check {
            name: "$BOOTINTEL_API_KEY",
            status: Status::Warn,
            detail: "unset — --api will need --preview (anonymous, 3/day per IP).\nGet a key at https://bootintel.com/settings/api-keys".into(),
        },
    }
}

fn check_history() -> Check {
    // Report where history writes go (or that they're opted out).
    // Always informational — never a Fail; history is a convenience,
    // not a requirement.
    let disabled = crate::history::is_disabled();
    let path = crate::history::history_path();
    match (disabled, path) {
        (true, _) => Check {
            name: "scan history",
            status: Status::Ok,
            detail: "disabled (BOOTINTEL_NO_HISTORY=1 or no_history=true in config).".into(),
        },
        (false, Some(p)) => Check {
            name: "scan history",
            status: Status::Ok,
            detail: format!(
                "enabled — appending to {}. Opt out with `bootintel config set no_history true` or BOOTINTEL_NO_HISTORY=1.",
                p.display()
            ),
        },
        (false, None) => Check {
            name: "scan history",
            status: Status::Warn,
            detail: "enabled but no platform state dir resolvable — writes will be no-ops.".into(),
        },
    }
}
