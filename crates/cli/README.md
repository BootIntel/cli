# bootintel-cli

Interactive UART capture + streaming boot-log analysis in one static Rust binary.

## Subcommands

- `bootintel scan <file>` — analyze a saved boot log
- `bootintel share <file>` — print a bootintel.com share URL for a local log
- `bootintel ports` — list serial ports available on this machine
- `bootintel version` — version, detector count, build info
- `bootintel term <port>` — interactive UART terminal
- `bootintel analyze <port>` — UART terminal + streaming analysis

## Build + run locally

```
cargo build --release
./target/release/bootintel version
./target/release/bootintel scan ../../samples/bootintel-4.txt --format text
```

## License

Apache-2.0.
