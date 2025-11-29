#!/usr/bin/env python3
"""
Basic Scanning Example

Demonstrates basic network scanning with NrMAP Python bindings.
"""

import asyncio
from nrmap import Scanner, quick_scan

async def main():
    print("=== NrMAP Python Bindings - Basic Scan Example ===\n")
    
    # Example 1: Quick scan using high-level API
    print("1. Quick Scan (High-level API)")
    target = "127.0.0.1"
    ports = [22, 80, 443, 8080]
    
    print(f"   Scanning {target} ports {ports}...")
    open_ports = await quick_scan(target, ports)
    print(f"   Open ports: {open_ports}\n")
    
    # Example 2: Using Scanner class directly
    print("2. Detailed Scan (Scanner Class)")
    scanner = Scanner()
    
    print(f"   Scanning {target} with multiple scan types...")
    result = await scanner.scan(target, ports, ["tcp"])
    
    print(f"   Target: {result['target']}")
    print(f"   Host Status: {result['host_status']}")
    print(f"   Scan Duration: {result['scan_duration_ms']}ms")
    
    print("\n   TCP Results:")
    for tcp_result in result['tcp_results']:
        status = "OPEN" if tcp_result['open'] else "CLOSED"
        print(f"     Port {tcp_result['port']}: {status} ({tcp_result['response_time_ms']}ms)")
    
    # Example 3: Multiple targets
    print("\n3. Multiple Targets")
    targets = ["127.0.0.1", "8.8.8.8"]
    
    for target in targets:
        try:
            open_ports = await quick_scan(target, [22, 80, 443], scan_type="tcp")
            print(f"   {target}: {len(open_ports)} open ports")
        except Exception as e:
            print(f"   {target}: Error - {e}")
    
    print("\n=== Example Complete ===")

if __name__ == "__main__":
    asyncio.run(main())

