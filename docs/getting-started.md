# Getting started with BootIntel CLI

BootIntel combines an interactive serial terminal with boot-log identification. Start with `bootintel term` for a focused UART console, or use `bootintel analyze` to see local findings while the device boots.

## Install a release

Download the archive for your operating system from [GitHub Releases](https://github.com/BootIntel/cli/releases/latest), download the matching `SHA256SUMS`, and verify the archive before extracting it. Place `bootintel` (or `bootintel.exe`) on your `PATH`.

Linux and macOS users may use the installer after reviewing it:

```sh
curl -sSfL https://raw.githubusercontent.com/BootIntel/cli/main/packaging/scripts/install.sh | sh
bootintel version
```

Windows users can use the release archive directly or run the documented PowerShell installer in the main README.

## First capture

1. Connect the UART adapter and run `bootintel ports`.
2. Identify the serial settings for the target. `115200 8N1` with no flow control is common, but the target documentation is authoritative.
3. Start a capture:

   ```sh
   bootintel analyze /dev/ttyUSB0 --baud 115200 --log-file boot.log
   ```

4. Power-cycle or reset the target if appropriate for your environment. BootIntel does not do this itself.
5. Press `Ctrl-A q` to quit. The raw bytes remain in `boot.log`; use `bootintel scan boot.log` to revisit them.

On Windows, write the port as `COM3`; on macOS it is commonly `/dev/cu.usbserial-*` or `/dev/cu.usbmodem*`.

## Hardware-free terminal check

On Linux or macOS, `socat` can create two connected pseudo-terminals:

```sh
socat -d -d pty,raw,echo=0 pty,raw,echo=0
# In another terminal, substitute the two printed /dev/pts/N paths.
bootintel analyze /dev/pts/N2 --log-file boot.log
printf 'U-Boot 2020.10\nHit any key to stop autoboot:  3\n' > /dev/pts/N1
```

This confirms terminal input, raw logging, and live local detection without attaching a device.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| No port in `bootintel ports` | Reconnect the adapter, try another USB cable or port, and check the operating system device list. Charge-only cables do not expose serial data. |
| Permission denied on Linux | Add the current user to the distribution's serial-access group (often `dialout`), then sign out and back in. Do not run the terminal as root by default. |
| Garbled text | Confirm baud rate, data bits, parity, stop bits, and flow control. A wrong baud rate is the usual cause. |
| No boot output | Check TX/RX are crossed, ground is shared, and the adapter uses the target's correct voltage level. Avoid attaching 5 V logic to a 3.3 V UART. |
| Device is busy | Close another terminal application, then retry. On Unix, BootIntel attempts an exclusive lock to prevent two readers sharing the port. |
| `--tui` is unavailable | Install a release built with the TUI feature, or build from source with `cargo build --release --features tui`. |

## Keep captures local

`bootintel term`, `bootintel analyze`, and `bootintel scan` use the local detector set by default. Only `--api` and `--api --preview` submit a log to BootIntel's API. Review a capture before sharing it: boot logs can include network configuration, host names, serial numbers, or credentials printed by device firmware.
