//! `bootintel ports` — list serial ports.
//!
//! Enumerates via `serialport::available_ports()`. Text format shows
//! path + USB VID:PID + product string; --json emits a structured
//! array so scripts can filter on VID/PID or bus type without regex.
//!
//! # Ordering
//!
//! USB ports come first, then everything else, each group sorted
//! naturally by port number.
//!
//! This matters because `available_ports()` returns whatever order the
//! platform enumerated in, and on a typical Linux box that is 32
//! motherboard `/dev/ttyS*` stubs in essentially random order. The one
//! port the user cares about — the USB adapter they just plugged in —
//! was somewhere in the middle of that wall of text with nothing to
//! distinguish it. The adapter is the answer to the question being
//! asked, so it goes at the top, labelled.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use serialport::SerialPortType;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Suppress the "no serial ports found" hint on empty output.
    #[arg(long)]
    quiet: bool,

    /// Machine-readable JSON output. Array of `{name, kind, ...}`
    /// entries with USB VID/PID + manufacturer / product / SN when
    /// available. Empty array on no ports (never "null").
    #[arg(long)]
    json: bool,
}

/// Sort key: USB first, then by a natural ordering of the port name so
/// `/dev/ttyS9` sorts before `/dev/ttyS10` instead of after it.
fn sort_key(p: &serialport::SerialPortInfo) -> (u8, String, u32, String) {
    let bus_rank = match &p.port_type {
        SerialPortType::UsbPort(_) => 0,
        SerialPortType::BluetoothPort => 1,
        SerialPortType::PciPort => 2,
        SerialPortType::Unknown => 3,
    };
    // Split the trailing digit run off so numbers compare as numbers.
    let name = &p.port_name;
    let digits_start = name
        .rfind(|c: char| !c.is_ascii_digit())
        .map(|i| i + 1)
        .unwrap_or(0);
    let (stem, num) = name.split_at(digits_start);
    (
        bus_rank,
        stem.to_string(),
        num.parse::<u32>().unwrap_or(0),
        name.clone(),
    )
}

pub fn run(args: Args) -> Result<()> {
    let mut ports = serialport::available_ports().context("enumerating serial ports")?;
    ports.sort_by_key(sort_key);

    if args.json {
        let items: Vec<serde_json::Value> = ports.iter().map(port_json).collect();
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        serde_json::to_writer_pretty(&mut out, &items)?;
        use std::io::Write;
        writeln!(out)?;
        return Ok(());
    }

    if ports.is_empty() {
        if !args.quiet {
            eprintln!("no serial ports found.");
            eprintln!();
            eprintln!("  Linux users may need to be in the `dialout` (or `uucp`) group:");
            eprintln!("    sudo usermod -aG dialout $USER   # then log out + back in");
            eprintln!();
            eprintln!("  On WSL, Windows COM ports are mapped as /dev/ttyS<N>.");
        }
        return Ok(());
    }
    let usb_count = ports
        .iter()
        .filter(|p| matches!(p.port_type, SerialPortType::UsbPort(_)))
        .count();

    // Pad the name column so the annotations line up into a readable
    // second column rather than ragging off each path.
    let width = ports
        .iter()
        .map(|p| p.port_name.chars().count())
        .max()
        .unwrap_or(0)
        .min(32);

    let mut printed_divider = false;
    for p in &ports {
        let is_usb = matches!(p.port_type, SerialPortType::UsbPort(_));
        // One blank line between the USB adapters and the built-in
        // ports, so the interesting group reads as a group.
        if !is_usb && usb_count > 0 && !printed_divider && !args.quiet {
            println!();
            printed_divider = true;
        }
        print!("{:width$}", p.port_name);
        match &p.port_type {
            SerialPortType::UsbPort(info) => {
                print!("  USB {:04x}:{:04x}", info.vid, info.pid);
                // The product string is how a human recognises their
                // adapter ("FT232R USB UART", "CP2102 USB to UART
                // Bridge Controller"), so it is the part that must
                // always show.
                match (&info.manufacturer, &info.product) {
                    (Some(m), Some(prod)) => print!("  {m} / {prod}"),
                    (None, Some(prod)) => print!("  {prod}"),
                    (Some(m), None) => print!("  {m}"),
                    (None, None) => print!("  (USB serial adapter)"),
                }
                if let Some(sn) = &info.serial_number {
                    print!("  SN={sn}");
                }
            }
            SerialPortType::PciPort => print!("  (PCI serial)"),
            SerialPortType::BluetoothPort => print!("  (Bluetooth)"),
            // Not "unknown" to a human: on Linux these are the
            // motherboard's 8250 stubs, which almost never have
            // anything attached.
            SerialPortType::Unknown => print!("  (built-in / no USB descriptor)"),
        }
        println!();
    }

    if !args.quiet && usb_count > 0 && ports.len() > usb_count {
        eprintln!();
        eprintln!(
            "  {usb_count} USB adapter(s) listed first; the remaining {} are built-in ports \n               with nothing attached in the usual case.",
            ports.len() - usb_count
        );
    }
    Ok(())
}

fn port_json(p: &serialport::SerialPortInfo) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "name": p.port_name,
        "kind": match &p.port_type {
            SerialPortType::UsbPort(_) => "usb",
            SerialPortType::PciPort => "pci",
            SerialPortType::BluetoothPort => "bluetooth",
            SerialPortType::Unknown => "unknown",
        },
    });
    if let SerialPortType::UsbPort(info) = &p.port_type {
        // Emit VID/PID as 4-digit lowercase hex strings so JSON
        // consumers can grep + match without integer conversions.
        obj["vid"] = serde_json::Value::String(format!("{:04x}", info.vid));
        obj["pid"] = serde_json::Value::String(format!("{:04x}", info.pid));
        if let Some(m) = &info.manufacturer {
            obj["manufacturer"] = serde_json::Value::String(m.clone());
        }
        if let Some(prod) = &info.product {
            obj["product"] = serde_json::Value::String(prod.clone());
        }
        if let Some(sn) = &info.serial_number {
            obj["serial_number"] = serde_json::Value::String(sn.clone());
        }
    }
    obj
}
