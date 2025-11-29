# NrMAP Python Quick Start Guide

Get started with NrMAP Python bindings in 5 minutes!

## 📋 Prerequisites

- Python 3.8 or higher
- Rust 1.70+ (for building from source)
- pip and maturin

## 🚀 Installation

### Quick Install

```bash
# Install maturin
pip install maturin

# Clone and build
git clone https://github.com/deepskilling/RUSTSCAN.git
cd RUSTSCAN

# Build and install (takes ~3 seconds)
maturin develop --release --features python

# Verify installation
python -c "import nrmap; print(f'NrMAP v{nrmap.__version__} ready!')"
```

### Or Use Makefile

```bash
make python-dev  # Build and install in one command
```

## 🎯 Basic Usage

### 1. Quick Port Scan

```python
import asyncio
from nrmap import quick_scan

async def main():
    # Scan common ports
    open_ports = await quick_scan("192.168.1.1", [22, 80, 443, 3389, 8080])
    print(f"Open ports: {open_ports}")

asyncio.run(main())
```

### 2. Detailed Network Scan

```python
import asyncio
from nrmap import Scanner

async def main():
    scanner = Scanner()
    
    # Scan with TCP connect
    result = await scanner.scan(
        "192.168.1.1",
        [22, 80, 443, 3389],
        ["tcp"]
    )
    
    print(f"Host: {result['target']}")
    print(f"Status: {result['host_status']}")
    print(f"Scan time: {result['scan_duration_ms']}ms")
    
    # Show open ports
    for port_info in result['tcp_results']:
        if "Open" in str(port_info):
            print(f"  Port {port_info['port']}: OPEN")

asyncio.run(main())
```

### 3. Service Detection

```python
import asyncio
from nrmap import DetectionEngine

async def main():
    engine = DetectionEngine()
    
    # Detect service on port 22
    service = await engine.detect_service("192.168.1.1", 22)
    
    print(f"Service: {service['name']}")
    print(f"Version: {service['version']}")
    print(f"Confidence: {service['confidence']}")

asyncio.run(main())
```

### 4. OS Fingerprinting

```python
import asyncio
from nrmap import OsFingerprintEngine

async def main():
    engine = OsFingerprintEngine()
    
    # Fingerprint and detect OS
    matches = await engine.detect_os("192.168.1.1", 22)
    
    if matches:
        best = matches[0]
        print(f"OS: {best['os_name']}")
        print(f"Confidence: {best['confidence_score']*100:.1f}%")
        print(f"Techniques: {len(best['matching_features'])}")

asyncio.run(main())
```

### 5. Complete Workflow

```python
import asyncio
from nrmap import scan_network, generate_report

async def main():
    # All-in-one scan with services and OS detection
    result = await scan_network(
        "192.168.1.1",
        [22, 80, 443],
        detect_services=True,
        detect_os=True
    )
    
    # Generate JSON report
    report = generate_report(result, "json", "scan_report.json")
    print("✅ Scan complete! Report saved to scan_report.json")

asyncio.run(main())
```

## 📚 Common Use Cases

### Scan Multiple Hosts

```python
import asyncio
from nrmap import quick_scan

async def scan_network(hosts, ports):
    tasks = [quick_scan(host, ports) for host in hosts]
    results = await asyncio.gather(*tasks)
    
    for host, open_ports in zip(hosts, results):
        if open_ports:
            print(f"{host}: {open_ports}")

# Scan subnet
hosts = [f"192.168.1.{i}" for i in range(1, 11)]
asyncio.run(scan_network(hosts, [22, 80, 443]))
```

### Save Results to File

```python
import asyncio
import json
from nrmap import Scanner

async def main():
    scanner = Scanner()
    result = await scanner.scan("192.168.1.1", [22, 80, 443], ["tcp"])
    
    # Save as JSON
    with open("scan_results.json", "w") as f:
        json.dump(result, f, indent=2)
    
    print("✅ Results saved!")

asyncio.run(main())
```

### Advanced OS Fingerprinting

```python
import asyncio
from nrmap import fingerprint_os

async def main():
    # Comprehensive fingerprinting (more techniques)
    fp = await fingerprint_os("192.168.1.1", 22, use_active_probes=False)
    
    print(f"Detection time: {fp['detection_time_ms']}ms")
    print(f"TCP fingerprinting: {fp['has_tcp']}")
    print(f"ICMP fingerprinting: {fp['has_icmp']}")
    print(f"Clock skew analysis: {fp['has_clock_skew']}")

asyncio.run(main())
```

## 🎨 Report Formats

Generate reports in multiple formats:

```python
from nrmap import generate_report

# Assume you have scan_data from a previous scan

# JSON (compact)
json_report = generate_report(scan_data, "json", "report.json")

# JSON (pretty)
pretty_json = generate_report(scan_data, "json_pretty", "report_pretty.json")

# YAML
yaml_report = generate_report(scan_data, "yaml", "report.yaml")

# HTML (styled)
html_report = generate_report(scan_data, "html", "report.html")

# Table (console)
table_report = generate_report(scan_data, "table")
print(table_report)
```

## ⚡ Performance Tips

### 1. Parallel Scanning

```python
import asyncio
from nrmap import Scanner

async def scan_parallel():
    scanner = Scanner()
    
    # Scan multiple targets in parallel
    tasks = [
        scanner.scan("192.168.1.1", [22, 80], ["tcp"]),
        scanner.scan("192.168.1.2", [22, 80], ["tcp"]),
        scanner.scan("192.168.1.3", [22, 80], ["tcp"])
    ]
    
    results = await asyncio.gather(*tasks)
    return results

results = asyncio.run(scan_parallel())
```

### 2. Reuse Scanner Instance

```python
# Good: Reuse scanner
scanner = Scanner()
result1 = await scanner.scan(target1, ports, ["tcp"])
result2 = await scanner.scan(target2, ports, ["tcp"])

# Avoid: Creating new scanner each time
# scanner = Scanner()  # Don't do this in a loop
```

## 🔒 Security Notes

### Privilege Requirements

Some scan types require elevated privileges:

```bash
# TCP SYN scan requires root/admin
sudo python scan_syn.py

# Or set capabilities (Linux only)
sudo setcap cap_net_raw+ep $(which python3)
```

### Active Probes Warning

```python
# Active probes are VERY intrusive - use carefully!
fp = await fingerprint_os(
    target, 
    port, 
    use_active_probes=True  # ⚠️ Will trigger IDS/IPS!
)
```

## 🐛 Troubleshooting

### Import Error

```python
# Error: ModuleNotFoundError: No module named 'nrmap'
# Solution: Rebuild and install
```

```bash
cd RUSTSCAN
maturin develop --release --features python
```

### Permission Denied

```python
# Error: Permission denied for raw sockets
# Solution: Run with sudo or set capabilities
```

```bash
sudo python your_script.py
```

### Asyncio Event Loop Error

```python
# Error: RuntimeError: no running event loop
# Solution: Use asyncio.run()
```

```python
# Good ✅
asyncio.run(main())

# Bad ❌
await main()  # Only works inside async functions
```

## 📖 Full Documentation

- **API Reference**: See `python/README.md`
- **Examples**: Check `python/examples/` directory
- **Main Docs**: See `README.md`

## 🎓 Next Steps

1. ✅ **Run the examples**: `python python/examples/basic_scan.py`
2. ✅ **Read python/README.md**: Full API documentation
3. ✅ **Explore examples/**: 4 complete working examples
4. ✅ **Run tests**: `pytest python/tests/`

## 💡 Quick Tips

✅ **Always use async/await** - All scan methods are asynchronous
✅ **Handle exceptions** - Wrap scans in try/except for production
✅ **Check permissions** - Some features need elevated privileges
✅ **Reuse objects** - Scanner and engine instances are thread-safe
✅ **Use quick_scan()** - For simple port scanning tasks

## 🚀 Ready to Go!

You're now ready to use NrMAP from Python. Start with the basic examples above and explore the full API in `python/README.md`.

**Happy Scanning!** 🎉

---

**Need Help?**
- GitHub Issues: https://github.com/deepskilling/RUSTSCAN/issues
- Full Docs: `python/README.md`
- Examples: `python/examples/`

