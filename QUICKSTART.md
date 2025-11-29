# NrMAP Quick Start Guide

## 🚀 Build the Project

```bash
# Navigate to the project directory
cd NrMAP

# Build in release mode
cargo build --release

# The binary will be at: target/release/nrmap
```

## 📋 Basic Usage

### 1. Simple Scan

Scan common ports on localhost:

```bash
./target/release/nrmap scan --target 127.0.0.1
```

### 2. Specify Ports

Scan specific ports:

```bash
./target/release/nrmap scan --target 192.168.1.1 --ports "80,443,22"
```

### 3. Port Range

Scan a range of ports:

```bash
./target/release/nrmap scan --target 192.168.1.1 --ports "1-1000"
```

### 4. Use Presets

Scan with predefined port lists:

```bash
# Web ports (80, 443, 8080, etc.)
./target/release/nrmap scan --target 192.168.1.1 --preset web

# Database ports
./target/release/nrmap scan --target 192.168.1.1 --preset database
```

### 5. Different Scan Types

```bash
# TCP Connect scan (default, no special privileges needed)
./target/release/nrmap scan --target 192.168.1.1 --scan-type tcp

# TCP SYN scan (requires root/sudo)
sudo ./target/release/nrmap scan --target 192.168.1.1 --scan-type syn

# UDP scan
./target/release/nrmap scan --target 192.168.1.1 --scan-type udp --preset common
```

### 6. Scan Multiple Targets

Create a file with target IPs:

```bash
echo "192.168.1.1" > targets.txt
echo "192.168.1.2" >> targets.txt
echo "192.168.1.3" >> targets.txt

# Scan all targets
./target/release/nrmap scan-file --file targets.txt --preset common
```

## ⚙️ Configuration

Edit `config.toml` to customize:

- **Logging**: Level, format, file output
- **Scan timeouts**: Connection and retry settings
- **Concurrency**: Max simultaneous scans
- **Throttling**: Adaptive rate control
- **Scan types**: Enable/disable TCP/UDP/SYN scans

## 📖 Example Session

```bash
# 1. Build the project
cargo build --release

# 2. Scan localhost for web services
./target/release/nrmap scan --target 127.0.0.1 --preset web

# Output:
================================================================================
Scan Results for 127.0.0.1
  Host Status: UP
  Scan Duration: 1234ms

  TCP Connect Results:
    127.0.0.1:80 - open (45ms) [HTTP/1.1 200 OK]
    127.0.0.1:443 - open (52ms)

  Throttle Stats: 1000 pps, 6/6 requests (100.00% success)
================================================================================
```

## 🔧 Library Usage

Use NrMAP as a library in your Rust project:

```toml
# Cargo.toml
[dependencies]
nrmap = { path = "/path/to/NrMAP" }
tokio = { version = "1", features = ["full"] }
```

```rust
use nrmap::{init_library, parse_port_range, ScanType};
use std::net::IpAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize
    let (scanner, _guard) = init_library(Some("config.toml")).await?;
    
    // Scan
    let target: IpAddr = "127.0.0.1".parse()?;
    let ports = parse_port_range("80,443,22")?;
    let scan_types = vec![ScanType::TcpConnect];
    
    let results = scanner.scan(target, ports, scan_types).await?;
    println!("{}", results);
    
    Ok(())
}
```

## 📂 Logs

Logs are saved to `./logs/` directory:

```bash
# View logs
tail -f logs/nrmap-$(date +%Y-%m-%d).log
```

## 🐛 Troubleshooting

### Permission Denied for SYN Scan

```bash
# Run with sudo
sudo ./target/release/nrmap scan --target 192.168.1.1 --scan-type syn
```

### Configuration Not Found

```bash
# Specify config path
./target/release/nrmap --config /path/to/config.toml scan --target 192.168.1.1
```

### Timeout Issues

Edit `config.toml` and increase timeouts:

```toml
[scanner.tcp_connect]
timeout_ms = 10000  # Increase from 5000
retries = 3         # Increase retries
```

## 🎯 Next Steps

1. Read the full [README.md](README.md) for detailed documentation
2. Explore the [examples/](examples/) directory
3. Check the [PRD.md](PRD.md) for project roadmap
4. Customize `config.toml` for your needs
5. Run tests: `cargo test`

## 💡 Tips

- Use `--verbose` flag for more detailed output
- Start with small port ranges for testing
- Use adaptive throttling to avoid network issues
- Check logs for detailed scan information
- SYN and UDP scans are less reliable than TCP connect

## ⚠️ Legal Notice

Only scan networks you own or have explicit permission to test. Unauthorized port scanning may be illegal in your jurisdiction.

