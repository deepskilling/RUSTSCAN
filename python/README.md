# NrMAP Python Bindings

High-performance Python bindings for NrMAP (Network Reconnaissance and Mapping Platform) built with PyO3.

## Features

### Phase 1: Core Scanner ✅
- Host discovery
- TCP connect scan
- TCP SYN scan (requires root/admin)
- UDP scan
- Adaptive throttling
- Quick scan convenience methods

### Phase 2: Detection Engine ✅
- Service banner grabbing
- Service fingerprinting
- Basic OS detection

### Phase 3: OS Fingerprinting ✅
- TCP/IP stack fingerprinting
- ICMP-based fingerprinting
- UDP-based fingerprinting
- Protocol/service hints
- Clock skew analysis
- Passive fingerprinting
- Active probe library (T1-T7, U1, IE, SEQ, ECN)
- Fuzzy matching engine
- 50+ built-in OS signatures

### Phase 4: Reporting ✅
- JSON output (compact and pretty)
- YAML output
- HTML reports
- CLI table formatting
- Custom report builders

## Installation

### Prerequisites

- Python 3.8 or higher
- Rust 1.70 or higher (for building from source)
- maturin (Python package build tool)

### Install from source

```bash
# Install maturin
pip install maturin

# Build and install in development mode
maturin develop --release --features python

# Or build a wheel
maturin build --release --features python
pip install target/wheels/nrmap-0.1.0-*.whl
```

### Install dependencies

```bash
pip install python-dotenv

# For development
pip install pytest pytest-asyncio black mypy
```

## Quick Start

### Basic Scanning

```python
import asyncio
from nrmap import quick_scan

async def main():
    # Quick scan for open ports
    open_ports = await quick_scan("192.168.1.1", [22, 80, 443])
    print(f"Open ports: {open_ports}")

asyncio.run(main())
```

### Comprehensive Scan

```python
import asyncio
from nrmap import Scanner

async def main():
    scanner = Scanner()
    
    # Scan with multiple scan types
    result = await scanner.scan(
        "192.168.1.1",
        [22, 80, 443, 3389],
        ["tcp", "syn"]
    )
    
    print(f"Host: {result['target']}")
    print(f"Status: {result['host_status']}")
    print(f"Duration: {result['scan_duration_ms']}ms")
    
    for port_info in result['tcp_results']:
        if port_info['open']:
            print(f"  Port {port_info['port']}: OPEN")

asyncio.run(main())
```

### Service Detection

```python
import asyncio
from nrmap import DetectionEngine

async def main():
    engine = DetectionEngine()
    
    # Grab banner
    banner = await engine.grab_banner("192.168.1.1", 22)
    print(f"Banner: {banner}")
    
    # Detect service
    service = await engine.detect_service("192.168.1.1", 22)
    print(f"Service: {service['name']} v{service['version']}")

asyncio.run(main())
```

### OS Fingerprinting

```python
import asyncio
from nrmap import OsFingerprintEngine

async def main():
    engine = OsFingerprintEngine()
    
    # Get database info
    db_info = engine.get_database_info()
    print(f"Database: {db_info['signature_count']} OS signatures")
    
    # Fingerprint target
    fingerprint = await engine.fingerprint("192.168.1.1", 22)
    print(f"Detection time: {fingerprint['detection_time_ms']}ms")
    print(f"TCP fingerprinting: {fingerprint['has_tcp']}")
    print(f"Clock skew analysis: {fingerprint['has_clock_skew']}")
    
    # Detect and match OS
    matches = await engine.detect_os("192.168.1.1", 22)
    if matches:
        best = matches[0]
        print(f"\nBest match: {best['os_name']}")
        print(f"Confidence: {best['confidence_score']*100:.1f}%")
        print(f"Matching features: {len(best['matching_features'])}")

asyncio.run(main())
```

### Report Generation

```python
from nrmap import generate_report

# Assume we have scan_results from a previous scan
scan_results = {
    "target": "192.168.1.1",
    "tcp_results": [{"port": 22, "open": True}]
}

# Generate JSON report
json_report = generate_report(scan_results, "json", "scan_report.json")
print(f"Report saved to scan_report.json")

# Generate YAML report
yaml_report = generate_report(scan_results, "yaml", "scan_report.yaml")

# Generate table report
table_report = generate_report(scan_results, "table")
print(table_report)
```

### Complete Network Scan

```python
import asyncio
from nrmap import scan_network

async def main():
    result = await scan_network(
        "192.168.1.1",
        [22, 80, 443, 3389],
        scan_types=["tcp"],
        detect_services=True,
        detect_os=True
    )
    
    print(f"Target: {result['target']}")
    print(f"Status: {result['host_status']}")
    
    if 'services' in result:
        print("\nServices:")
        for port, service in result['services'].items():
            print(f"  Port {port}: {service.get('name', 'Unknown')}")
    
    if 'os' in result and result['os']:
        print(f"\nOS: {result['os']['os_name']}")
        print(f"Confidence: {result['os']['confidence_score']*100:.1f}%")

asyncio.run(main())
```

## API Reference

### Scanner Class

```python
Scanner(config_path: Optional[str] = None)
```

**Methods:**
- `scan(target, ports, scan_types)` - Perform comprehensive scan
- `quick_scan(target, ports)` - Quick TCP scan
- `discover_hosts(targets)` - Find live hosts
- `get_stats()` - Get scanner statistics

### DetectionEngine Class

```python
DetectionEngine()
```

**Methods:**
- `grab_banner(target, port, timeout_ms)` - Grab service banner
- `detect_service(target, port)` - Identify service
- `detect_os(target, port)` - Basic OS detection
- `detect_all(target, port)` - Complete detection

### OsFingerprintEngine Class

```python
OsFingerprintEngine()
```

**Methods:**
- `fingerprint(target, open_port, closed_port, use_active_probes)` - Complete OS fingerprint
- `detect_os(target, open_port, closed_port, use_active_probes)` - Detect and match OS
- `get_database_info()` - Get database statistics

### ReportEngine Class

```python
ReportEngine()
```

**Methods:**
- `generate_report(scan_data, format, output_path)` - Generate report
- `builder()` - Create report builder for customization

### High-level API Functions

- `quick_scan(target, ports, scan_type)` - Quick port scan
- `scan_network(target, ports, scan_types, detect_services, detect_os)` - Comprehensive scan
- `detect_os(target, open_port, use_active_probes)` - OS detection (blocking)
- `fingerprint_os(target, open_port, closed_port, use_active_probes)` - Complete fingerprinting
- `generate_report(scan_data, format, output_path)` - Generate report

## Configuration

Create a `config.toml` file or use the default configuration:

```toml
[scanner]
default_timeout_ms = 5000
max_concurrent_scans = 100

[os_fingerprint]
enable_tcp_fingerprinting = true
enable_clock_skew = true
enable_active_probes = false  # Very intrusive!
```

Pass config file to Scanner:

```python
scanner = Scanner("custom_config.toml")
```

## Performance

- **Async/Await**: Full async support with Python's asyncio
- **Native Speed**: Rust backend provides near-native performance
- **Parallel Scans**: Handles thousands of concurrent connections
- **Low Overhead**: Minimal Python-to-Rust conversion cost

## Examples

See the `examples/` directory for comprehensive examples:

- `basic_scan.py` - Basic scanning operations
- `detection_example.py` - Service and OS detection
- `reporting_example.py` - Report generation
- `advanced_fingerprinting.py` - Advanced OS fingerprinting

Run examples:

```bash
python3 python/examples/basic_scan.py
python3 python/examples/detection_example.py
```

## Testing

```bash
# Run Python tests
pytest

# Run with coverage
pytest --cov=nrmap --cov-report=html

# Run specific test
pytest tests/test_scanner.py
```

## Contributing

Contributions are welcome! Please ensure:

1. Code passes `black` formatting
2. Type hints where possible
3. Comprehensive docstrings
4. Tests for new features
5. Update documentation

## License

MIT License - See LICENSE file for details

## Security Notice

Some features (like SYN scan and active probes) require elevated privileges and can be intrusive. Always obtain proper authorization before scanning networks you don't own.

**Active Probes Warning**: Active OS fingerprinting probes are very intrusive and will trigger IDS/IPS systems. Use only on networks you have explicit permission to scan.

## Support

- GitHub Issues: https://github.com/deepskilling/RUSTSCAN/issues
- Documentation: See README.md and PRD.md

## Acknowledgments

Built with:
- PyO3 - Rust-Python bindings
- Tokio - Async runtime
- pyo3-asyncio - Async bridge

---

**Version**: 0.1.0
**Status**: Production-ready
**Python Support**: 3.8+

