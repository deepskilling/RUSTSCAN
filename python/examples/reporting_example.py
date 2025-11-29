#!/usr/bin/env python3
"""
Reporting Example

Demonstrates report generation in various formats.
"""

import asyncio
from nrmap import Scanner, ReportEngine, ReportFormat, generate_report

async def main():
    print("=== NrMAP Python Bindings - Reporting Example ===\n")
    
    target = "192.168.1.100"
    ports = [22, 80, 443, 3306, 5432, 8080]
    
    # Perform scan
    print("1. Performing scan...")
    scanner = Scanner()
    scan_data = await scanner.scan(target, ports, ["tcp"])
    print(f"   Scanned {target}: {scan_data['scan_duration_ms']}ms\n")
    
    # Generate reports in different formats
    report_engine = ReportEngine()
    
    # Example 1: JSON Report
    print("2. JSON Report")
    json_report = report_engine.generate_report(scan_data, "json")
    print(f"   Generated JSON report ({len(json_report)} bytes)")
    print(f"   Preview: {json_report[:100]}...\n")
    
    # Example 2: YAML Report
    print("3. YAML Report")
    yaml_report = report_engine.generate_report(scan_data, "yaml")
    print(f"   Generated YAML report ({len(yaml_report)} bytes)")
    print(f"   Preview: {yaml_report[:100]}...\n")
    
    # Example 3: Table Report
    print("4. Table Report")
    table_report = report_engine.generate_report(scan_data, "table")
    print("   Generated Table report:")
    print(table_report)
    print()
    
    # Example 4: Save to file
    print("5. Save Reports to Files")
    formats = ["json", "yaml", "table"]
    for fmt in formats:
        filename = f"scan_report.{fmt}"
        report = report_engine.generate_report(scan_data, fmt, filename)
        print(f"   ✓ Saved {fmt.upper()} report to {filename}")
    print()
    
    # Example 5: High-level API
    print("6. Using High-level API")
    report = generate_report(scan_data, "json_pretty", "scan_report_pretty.json")
    print(f"   ✓ Generated pretty JSON report\n")
    
    # Available formats
    print("7. Available Formats")
    formats = ReportFormat.available_formats()
    print(f"   Supported formats: {', '.join(formats)}\n")
    
    print("=== Example Complete ===")

if __name__ == "__main__":
    asyncio.run(main())

