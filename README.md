# NrMAP - High-Performance Network Scanner

A blazingly fast, Nmap-like network scanner written in Rust with comprehensive logging, exception handling, and configuration management.

## 🚀 Features

- **Multiple Scan Types**
  - TCP Connect Scan (full three-way handshake)
  - TCP SYN Scan (half-open scan, requires elevated privileges)
  - UDP Scan with service-specific probes

- **Host Discovery**
  - ICMP ping
  - TCP-based discovery
  - UDP-based discovery
  - ARP discovery (local networks)

- **Adaptive Throttling**
  - Intelligent rate limiting
  - Automatic speed adjustment based on success rates
  - Prevents network congestion and rate limiting

- **Comprehensive Logging**
  - Multiple log levels (trace, debug, info, warn, error)
  - File and console output
  - JSON and text formats
  - Performance tracking
  - Log rotation

- **Robust Error Handling**
  - Custom error types for all scenarios
  - Error severity levels
  - Retry mechanisms with configurable delays
  - Detailed error context

- **Single Configuration File**
  - TOML-based configuration
  - All settings in one place
  - Extensive validation
  - Sensible defaults

## 📋 Requirements

- Rust 1.70 or higher
- Elevated privileges (root/administrator) for:
  - TCP SYN scan
  - ICMP ping
  - Raw socket operations

## 🔧 Installation

### From Source

```bash
git clone <repository-url>
cd NrMAP
cargo build --release
```

The compiled binary will be in `target/release/nrmap`.

### Using Cargo

```bash
cargo install --path .
```

## ⚙️ Configuration

NrMAP uses a single `config.toml` file for all settings. A sample configuration is provided in the repository.

### Key Configuration Sections

```toml
[general]
app_name = "NrMAP"
version = "0.1.0"

[logging]
level = "info"              # trace, debug, info, warn, error
format = "text"             # text or json
file_logging = true
log_dir = "./logs"

[scanner]
default_timeout_ms = 5000
max_concurrent_scans = 1000
adaptive_throttling = true
initial_pps = 1000          # packets per second
max_pps = 10000
min_pps = 100

[scanner.tcp_connect]
enabled = true
timeout_ms = 5000
retries = 1

[scanner.tcp_syn]
enabled = true              # requires root/admin
timeout_ms = 3000
retries = 2

[scanner.udp]
enabled = true
timeout_ms = 5000
retries = 3

[throttling]
enabled = true
success_threshold = 0.95
failure_threshold = 0.80
rate_increase_factor = 1.5
rate_decrease_factor = 0.5
```

See `config.toml` for complete configuration options.

## 🎯 Usage

### Basic Scan

```bash
# Scan common ports on a target
nrmap scan --target 192.168.1.1

# Scan specific ports
nrmap scan --target 192.168.1.1 --ports "80,443,8080"

# Scan a port range
nrmap scan --target 192.168.1.1 --ports "1-1000"

# Use port presets
nrmap scan --target 192.168.1.1 --preset web
nrmap scan --target 192.168.1.1 --preset common
```

### Multiple Scan Types

```bash
# TCP connect scan (default)
nrmap scan --target 192.168.1.1 --scan-type tcp

# TCP SYN scan (requires root)
sudo nrmap scan --target 192.168.1.1 --scan-type syn

# UDP scan
nrmap scan --target 192.168.1.1 --scan-type udp

# Multiple scan types
sudo nrmap scan --target 192.168.1.1 --scan-type tcp --scan-type syn --scan-type udp
```

### Scan Multiple Targets

```bash
# Create a file with target IPs (one per line)
echo "192.168.1.1" > targets.txt
echo "192.168.1.2" >> targets.txt

# Scan all targets
nrmap scan-file --file targets.txt --ports "80,443"
```

### Custom Configuration

```bash
# Use a custom config file
nrmap --config /path/to/config.toml scan --target 192.168.1.1
```

### Port Presets

- `common` / `top100` - Most common 20 ports
- `web` - Web service ports (80, 443, 8080, etc.)
- `mail` - Email service ports (25, 110, 143, etc.)
- `database` - Database ports (3306, 5432, etc.)
- `all` - All ports (1-65535)

## 📊 Output Example

```
================================================================================
Scan Results for 192.168.1.1
  Host Status: UP
  Scan Duration: 2543ms

  TCP Connect Results:
    192.168.1.1:22 - open (124ms) [SSH-2.0-OpenSSH_8.9]
    192.168.1.1:80 - open (89ms) [HTTP/1.1 200 OK]
    192.168.1.1:443 - open (95ms)

  Throttle Stats: 1250 pps, 145/150 requests (96.67% success)
================================================================================
```

## 🏗️ Architecture

```
nrmap/
├── src/
│   ├── config/          # Configuration management
│   │   └── mod.rs       # TOML config loading & validation
│   ├── error.rs         # Comprehensive error handling
│   ├── logging.rs       # Logging system setup
│   ├── scanner/         # Scanner implementations
│   │   ├── mod.rs       # Scanner orchestrator
│   │   ├── host_discovery.rs
│   │   ├── tcp_connect.rs
│   │   ├── tcp_syn.rs
│   │   ├── udp_scan.rs
│   │   └── throttle.rs  # Adaptive throttling
│   ├── lib.rs           # Library interface
│   └── main.rs          # CLI application
├── config.toml          # Configuration file
├── Cargo.toml           # Dependencies
└── README.md
```

## 🔐 Security Considerations

1. **Elevated Privileges**: SYN scans and ICMP require root/administrator privileges
2. **Rate Limiting**: Use adaptive throttling to avoid overwhelming networks
3. **Legal**: Only scan networks you own or have permission to test
4. **Firewall Rules**: Some scans may trigger IDS/IPS systems

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test module
cargo test scanner::tcp_connect
```

## 📝 Logging

Logs are written to the `logs/` directory (configurable) with:
- Daily rotation
- Configurable retention
- Size limits
- Both console and file output
- Structured logging support (JSON)

Example log locations:
- `./logs/nrmap-2024-01-15.log`
- Console output (stdout)

## 🐛 Error Handling

NrMAP implements comprehensive error handling with:

- **Custom Error Types**: Specific errors for each operation
- **Error Severity Levels**: Critical, High, Medium, Low
- **Retry Logic**: Configurable retries with exponential backoff
- **Error Context**: Detailed context for debugging
- **Graceful Degradation**: Falls back to alternative methods when possible

## 🚀 Performance

- **Async I/O**: Uses Tokio for high-performance async operations
- **Concurrent Scanning**: Configurable concurrency limits
- **Adaptive Throttling**: Automatically adjusts speed for optimal performance
- **Memory Efficient**: Streaming results, minimal allocations

## 📚 Library Usage

NrMAP can also be used as a library:

```rust
use nrmap::{init_library, ScanType};
use std::net::IpAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize with config file
    let (scanner, _guard) = init_library(Some("config.toml")).await?;
    
    // Parse target
    let target: IpAddr = "192.168.1.1".parse()?;
    
    // Define ports and scan types
    let ports = vec![80, 443, 22, 21];
    let scan_types = vec![ScanType::TcpConnect];
    
    // Perform scan
    let results = scanner.scan(target, ports, scan_types).await?;
    
    // Process results
    println!("Scan completed in {}ms", results.scan_duration_ms);
    for tcp_result in results.tcp_results {
        println!("{}", tcp_result);
    }
    
    Ok(())
}
```

## 🤝 Contributing

Contributions are welcome! Please ensure:
- Code follows Rust best practices
- All tests pass
- New features include tests
- Documentation is updated

## 📄 License

MIT License - see LICENSE file for details

## 🙏 Acknowledgments

- Inspired by Nmap
- Built with Rust and Tokio
- Uses pnet for packet crafting (future enhancement)

## 🗺️ Roadmap

- [ ] Full raw socket implementation for SYN scans
- [ ] ICMP ping implementation
- [ ] Service version detection
- [ ] OS fingerprinting
- [ ] Output formats (JSON, YAML, XML)
- [ ] Integration with Nmap scripts
- [ ] Distributed scanning support
- [ ] Web UI / Dashboard
- [ ] REST API

## 📞 Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check documentation in `docs/`
- Review examples in `examples/`

---

**Note**: This tool is for authorized security testing only. Unauthorized port scanning may be illegal in your jurisdiction.

