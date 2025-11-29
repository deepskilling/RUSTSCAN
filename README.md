<div align="center">

# 🗺️ NrMAP

### High-Performance Network Reconnaissance and Mapping Platform

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](./CONTRIBUTING.md)

**A blazingly fast, Nmap-inspired network scanner built with Rust**  
_Production-quality packet crafting • Full IPv6 support • Python bindings • Advanced OS fingerprinting_

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Python Bindings](#-python-bindings) • [Documentation](#-documentation)

</div>

---

## 🎯 Overview

NrMAP is a modern, high-performance network reconnaissance platform written in Rust. Inspired by Nmap, it provides comprehensive scanning capabilities with advanced features like OS fingerprinting, service detection, and adaptive throttling. Built with production-quality packet crafting using `pnet`, NrMAP offers both native Rust performance and easy-to-use Python bindings.

### Why NrMAP?

- ⚡ **Blazingly Fast**: Asynchronous I/O with Tokio for maximum throughput
- 🌐 **Full IPv6 Support**: Production-quality packet crafting with pnet library
- 🐍 **Python-Ready**: Complete Python bindings via PyO3
- 🔍 **Advanced Fingerprinting**: Nmap-style OS detection and service identification
- 📊 **Rich Reporting**: JSON, YAML, HTML, and table formats
- 🎯 **Intelligent Throttling**: Adaptive rate limiting to prevent network congestion
- 🔐 **Security-First**: Comprehensive error handling and input validation

---

## ✨ Features

### 🔎 Scanning Capabilities

- **Multiple Scan Types**
  - TCP Connect Scan (full three-way handshake)
  - TCP SYN Scan (half-open scan, requires elevated privileges)
  - UDP Scan with service-specific probes

- **Host Discovery**
  - ICMP Echo (ping)
  - TCP-based discovery (SYN/ACK probes)
  - UDP-based discovery
  - ARP discovery for local networks

### 🖥️ OS Fingerprinting

- **TCP/IP Stack Fingerprinting**
  - TTL analysis, window size detection
  - MSS, DF flag, IP ID patterns
  - TCP options and ECN support
  - RST packet behavior analysis

- **Advanced Techniques**
  - ICMP-based fingerprinting
  - UDP response analysis
  - Protocol-specific hints (SSH, SMB, HTTP, TLS)
  - Clock skew analysis
  - Passive fingerprinting

- **Nmap-Style Probes**
  - TCP T1-T7 probe set
  - UDP U1 probe
  - ICMP IE probe
  - SEQ/ECN probes

### 📊 Reporting & Output

- **Multiple Formats**
  - JSON (structured data)
  - YAML (human-readable)
  - HTML (interactive reports)
  - Table (terminal-friendly)

- **Detailed Information**
  - Open/closed port status
  - Service detection results
  - OS fingerprint matches with confidence scores
  - Scan timing and performance metrics

### 🐍 Python Bindings

Complete Python API with async support:
```python
import asyncio
from nrmap import scan_ports

async def main():
    results = await scan_ports("192.168.1.1", [22, 80, 443])
    print(f"Open ports: {results}")

asyncio.run(main())
```

### 🛠️ Additional Features

- **Adaptive Throttling**: Automatic rate adjustment based on network conditions
- **Comprehensive Logging**: Multi-level, structured logging with rotation
- **Robust Error Handling**: Custom error types with detailed context
- **Single Config File**: TOML-based configuration with validation
- **Distributed Scanning**: Multi-agent architecture for large-scale scanning

---

## 📋 Requirements

### System Requirements

- **Operating System**: Linux, macOS, Windows
- **Rust**: 1.70 or higher
- **Python**: 3.8+ (for Python bindings)

### Privileges

Elevated privileges (root/administrator) required for:
- TCP SYN scan
- ICMP ping
- Raw socket operations
- Packet crafting

---

## 🚀 Installation

### From Source (Rust)

```bash
# Clone the repository
git clone https://github.com/deepskilling/RUSTSCAN.git
cd RUSTSCAN

# Build with Cargo
cargo build --release

# Run
sudo ./target/release/nrmap --help
```

### Python Bindings

```bash
# Install maturin (Rust-Python build tool)
pip install maturin

# Build and install Python package
maturin develop --release

# Or build wheel for distribution
maturin build --release
```

### Quick Install (Python)

```bash
# From project directory
pip install .
```

---

## 🎯 Quick Start

### Basic Rust Usage

```rust
use nrmap::scanner::Scanner;
use nrmap::config::AppConfig;
use std::net::IpAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::from_file("config.toml")?;
    let scanner = Scanner::new(config)?;
    
    let target: IpAddr = "192.168.1.1".parse()?;
    let ports = vec![22, 80, 443, 8080];
    
    let results = scanner.scan(target, &ports, &["tcp_connect"]).await?;
    println!("Scan results: {:?}", results);
    
    Ok(())
}
```

### Python Quick Start

```python
import asyncio
from nrmap import scan_ports, detect_os, generate_report

async def main():
    # Quick scan
    target = "192.168.1.1"
    ports = [22, 80, 443, 3389, 8080]
    
    # Scan for open ports
    open_ports = await scan_ports(target, ports)
    print(f"Open ports on {target}: {open_ports}")
    
    # OS fingerprinting
    os_info = await detect_os(target)
    print(f"OS Detection: {os_info['os_name']} (confidence: {os_info['confidence']}%)")
    
    # Generate report
    report = await generate_report(target, "json")
    print(f"Report saved: {report}")

if __name__ == "__main__":
    asyncio.run(main())
```

### Command Line

```bash
# TCP Connect scan
nrmap scan --target 192.168.1.0/24 --ports 22,80,443 --scan-type tcp_connect

# SYN scan (requires root)
sudo nrmap scan --target 192.168.1.1 --ports 1-1000 --scan-type syn

# OS fingerprinting
sudo nrmap fingerprint --target 192.168.1.1

# Generate HTML report
nrmap report --input scan_results.json --format html --output report.html
```

---

## 🐍 Python Bindings

### Installation

```bash
# Install with pip (from project directory)
pip install .

# Or using maturin for development
pip install maturin
maturin develop --release
```

### Complete Python API

```python
from nrmap import (
    PyScanner,
    PyDetectionEngine,
    PyOsFingerprintEngine,
    PyReportEngine,
    PyReportFormat
)

# Create scanner instance
scanner = PyScanner("config.toml")

# Scan multiple targets
results = await scanner.scan_multiple(
    ["192.168.1.1", "192.168.1.2"],
    [22, 80, 443],
    ["tcp_connect"]
)

# OS detection
detector = PyDetectionEngine()
os_info = await detector.detect_os("192.168.1.1")

# Generate reports
report_engine = PyReportEngine()
report_engine.generate("scan_results.json", PyReportFormat.HTML, "report.html")
```

See [PYTHON_QUICKSTART.md](./PYTHON_QUICKSTART.md) for complete Python documentation.

---

## 📚 Documentation

### Core Documentation

- **[Quick Start Guide](./PYTHON_QUICKSTART.md)** - Get started with Python bindings
- **[Product Requirements](./PRD.md)** - Detailed feature specifications
- **[API Documentation](./python/README.md)** - Python API reference
- **[Examples](./examples/)** - Rust code examples
- **[Python Examples](./python/examples/)** - Python code examples

### Configuration

Edit `config.toml` to customize:

```toml
[scanner]
default_timeout_ms = 1000
max_concurrent_scans = 100
enable_adaptive_throttling = true

[tcp_syn]
enabled = true
timeout_ms = 500
retries = 2

[logging]
level = "info"
file_output = true
console_output = true
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│              NrMAP Core (Rust)                  │
├─────────────────────────────────────────────────┤
│  Scanner Engine                                 │
│  ├── TCP Connect Scan                           │
│  ├── TCP SYN Scan                               │
│  ├── UDP Scan                                   │
│  └── Host Discovery                             │
├─────────────────────────────────────────────────┤
│  Packet Engine (pnet)                           │
│  ├── IPv4/IPv6 Packet Crafting                  │
│  ├── Automatic Checksums                        │
│  └── Zero-Copy Parsing                          │
├─────────────────────────────────────────────────┤
│  OS Fingerprinting                              │
│  ├── Active Probes (Nmap-style)                 │
│  ├── Passive Analysis                           │
│  └── Fuzzy Matching                             │
├─────────────────────────────────────────────────┤
│  Detection & Reporting                          │
│  ├── Service Detection                          │
│  ├── Banner Grabbing                            │
│  └── Multi-Format Reports                       │
└─────────────────────────────────────────────────┘
                      ↓
           ┌────────────────────┐
           │  Python Bindings   │
           │     (PyO3)         │
           └────────────────────┘
```

---

## 🧪 Testing

### Rust Tests

```bash
# Run all tests
cargo test

# Run with logging
RUST_LOG=debug cargo test

# Run specific test
cargo test test_tcp_scan
```

### Python Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run tests
pytest python/tests/

# With coverage
pytest --cov=nrmap python/tests/
```

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone repository
git clone https://github.com/deepskilling/RUSTSCAN.git
cd RUSTSCAN

# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cargo build

# Run tests
cargo test

# Install Python dev dependencies
pip install -e ".[dev]"
```

### Code Style

- **Rust**: `rustfmt` and `clippy`
- **Python**: `black` and `mypy`

```bash
# Format Rust code
cargo fmt

# Run Clippy
cargo clippy

# Format Python code
black python/
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

---

## 🙏 Acknowledgments

- Inspired by [Nmap](https://nmap.org/) - The legendary network scanner
- Built with [pnet](https://github.com/libpnet/libpnet) - Production-quality packet crafting
- Python bindings via [PyO3](https://github.com/PyO3/pyo3) - Rust ❤️ Python

---

## 🔗 Links

- **GitHub**: [https://github.com/deepskilling/RUSTSCAN](https://github.com/deepskilling/RUSTSCAN)
- **Issues**: [Report a bug or request a feature](https://github.com/deepskilling/RUSTSCAN/issues)
- **Discussions**: [Join the conversation](https://github.com/deepskilling/RUSTSCAN/discussions)

---

## 📊 Project Stats

- **Language**: Rust 🦀
- **Lines of Code**: ~15,000+
- **Test Coverage**: 182 tests passing
- **Dependencies**: Production-tested crates
- **Python Support**: Full async API

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing and network administration** only. Users are responsible for complying with all applicable laws and regulations. Unauthorized scanning of networks you don't own or have permission to test is illegal.

---

<div align="center">

**Made with ❤️ and Rust 🦀**

[⬆ Back to top](#-nrmap)

</div>
