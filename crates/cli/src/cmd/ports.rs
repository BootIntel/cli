//! `bootintel ports` — list serial ports.
//!
//! Enumerates via `serialport::available_ports()`. Text format shows
//! path + USB VID:PID + product string; --json emits a structured
//! array so scripts can filter on VID/PID or bus type without regex.

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

pub fn run(args: Args) -> Result<()> {
    let ports = serialport::available_ports().context("enumerating serial ports")?;

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
    for p in &ports {
        print!("{}", p.port_name);
        match &p.port_type {
            SerialPortType::UsbPort(info) => {
                print!("  USB {:04x}:{:04x}", info.vid, info.pid);
                if let Some(m) = &info.manufacturer {
                    print!("  {m}");
                }
                if let Some(prod) = &info.product {
                    print!(" / {prod}");
                }
                if let Some(sn) = &info.serial_number {
                    print!("  SN={sn}");
                }
            }
            SerialPortType::PciPort => print!("  (PCI serial)"),
            SerialPortType::BluetoothPort => print!("  (Bluetooth)"),
            SerialPortType::Unknown => {}
        }
        println!();
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
