#!/usr/bin/env python3
"""
Complete Workflow Example

Demonstrates a comprehensive scanning workflow combining all features.
"""

import asyncio
import json
from nrmap import (
    Scanner,
    DetectionEngine,
    OsFingerprintEngine,
    generate_report,
    scan_network
)

async def complete_scan_workflow(target: str, ports: list):
    """
    Perform a complete scanning workflow
    
    1. Host discovery
    2. Port scanning
    3. Service detection
    4. OS fingerprinting
    5. Report generation
    """
    print("=" * 70)
    print("NrMAP Complete Scanning Workflow")
    print("=" * 70)
    print()
    
    # Step 1: Initialize engines
    print("📦 Initializing scan engines...")
    scanner = Scanner()
    detection_engine = DetectionEngine()
    os_engine = OsFingerprintEngine()
    print(f"   ✓ Scanner ready")
    print(f"   ✓ Detection engine ready")
    print(f"   ✓ OS fingerprint engine ready ({os_engine.get_database_info()['signature_count']} signatures)")
    print()
    
    # Step 2: Host discovery and port scanning
    print(f"🔍 Step 1: Scanning {target}...")
    scan_result = await scanner.scan(target, ports, ["tcp"])
    
    print(f"   Target: {scan_result['target']}")
    print(f"   Status: {scan_result['host_status']}")
    print(f"   Scan duration: {scan_result['scan_duration_ms']}ms")
    
    open_ports = [p['port'] for p in scan_result['tcp_results'] if p['open']]
    print(f"   Open ports: {open_ports}")
    print()
    
    if not open_ports:
        print("⚠️  No open ports found. Exiting.")
        return
    
    # Step 3: Service detection
    print("🔎 Step 2: Service Detection...")
    services = {}
    
    for port in open_ports[:5]:  # Limit to first 5 ports for demo
        try:
            print(f"   Analyzing port {port}...")
            service = await detection_engine.detect_service(target, port)
            services[port] = service
            print(f"      → {service['name']} (v{service['version']}, confidence: {service['confidence']:.2f})")
        except Exception as e:
            print(f"      → Error: {e}")
    print()
    
    # Step 4: OS fingerprinting
    print("🖥️  Step 3: OS Fingerprinting...")
    first_open_port = open_ports[0]
    
    try:
        print(f"   Using port {first_open_port} for fingerprinting...")
        
        # Get fingerprint
        fingerprint = await os_engine.fingerprint(target, first_open_port)
        print(f"   Detection time: {fingerprint['detection_time_ms']}ms")
        
        print("   Techniques used:")
        if fingerprint['has_tcp']:
            print("     ✓ TCP/IP Stack Analysis")
        if fingerprint['has_icmp']:
            print("     ✓ ICMP-Based Analysis")
        if fingerprint['has_clock_skew']:
            print("     ✓ Clock Skew Analysis")
            if 'clock_skew' in fingerprint and 'skew_ppm' in fingerprint['clock_skew']:
                print(f"       Clock skew: {fingerprint['clock_skew']['skew_ppm']:.2f} ppm")
        
        # Match OS
        print()
        print("   Matching against OS database...")
        os_matches = await os_engine.detect_os(target, first_open_port)
        
        if os_matches:
            print(f"   Top matches ({len(os_matches)} total):")
            for i, match in enumerate(os_matches[:3], 1):
                conf = match['confidence_score'] * 100
                print(f"     {i}. {match['os_name']}")
                print(f"        Version: {match.get('os_version', 'Unknown')}")
                print(f"        Family: {match['os_family']}")
                print(f"        Confidence: {conf:.1f}%")
                print(f"        Features matched: {len(match['matching_features'])}")
    except Exception as e:
        print(f"   ⚠️  OS fingerprinting failed: {e}")
        os_matches = []
    print()
    
    # Step 5: Generate comprehensive report
    print("📊 Step 4: Generating Reports...")
    
    # Compile all data
    complete_results = {
        "target": target,
        "scan_timestamp": scan_result.get('scan_duration_ms', 0),
        "host_status": scan_result['host_status'],
        "open_ports": open_ports,
        "tcp_results": scan_result['tcp_results'],
        "services": services,
        "os_detection": {
            "matches": os_matches[:3] if os_matches else [],
            "fingerprint_data": {
                "detection_time_ms": fingerprint.get('detection_time_ms', 0) if 'fingerprint' in locals() else 0,
                "techniques": {
                    "tcp": fingerprint.get('has_tcp', False) if 'fingerprint' in locals() else False,
                    "icmp": fingerprint.get('has_icmp', False) if 'fingerprint' in locals() else False,
                    "clock_skew": fingerprint.get('has_clock_skew', False) if 'fingerprint' in locals() else False,
                }
            }
        }
    }
    
    # Generate JSON report
    json_report = generate_report(complete_results, "json_pretty", "complete_scan_report.json")
    print("   ✓ JSON report saved to: complete_scan_report.json")
    
    # Generate YAML report
    yaml_report = generate_report(complete_results, "yaml", "complete_scan_report.yaml")
    print("   ✓ YAML report saved to: complete_scan_report.yaml")
    
    # Generate table report
    table_report = generate_report(complete_results, "table")
    print("   ✓ Table report generated")
    print()
    
    # Display summary
    print("=" * 70)
    print("📋 SCAN SUMMARY")
    print("=" * 70)
    print(f"Target:       {target}")
    print(f"Open Ports:   {len(open_ports)}")
    print(f"Services:     {len(services)} detected")
    if os_matches:
        best_match = os_matches[0]
        print(f"OS Detected:  {best_match['os_name']} ({best_match['confidence_score']*100:.1f}% confidence)")
    print("=" * 70)
    print()
    print("✅ Workflow complete!")
    print()

async def main():
    """Main entry point"""
    # Example targets (adjust as needed)
    target = "192.168.1.100"
    ports = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080]
    
    print()
    print("⚠️  IMPORTANT NOTES:")
    print("  • Ensure you have permission to scan the target")
    print("  • Some features require elevated privileges")
    print("  • Adjust target and ports as needed")
    print()
    
    try:
        await complete_scan_workflow(target, ports)
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())

