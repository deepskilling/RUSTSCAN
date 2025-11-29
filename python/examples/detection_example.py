#!/usr/bin/env python3
"""
Detection Engine Example

Demonstrates service and OS detection capabilities.
"""

import asyncio
from nrmap import DetectionEngine, OsFingerprintEngine

async def main():
    print("=== NrMAP Python Bindings - Detection Example ===\n")
    
    target = "192.168.1.100"
    port = 22
    
    # Example 1: Banner Grabbing
    print("1. Banner Grabbing")
    detection = DetectionEngine()
    
    print(f"   Grabbing banner from {target}:{port}...")
    try:
        banner = await detection.grab_banner(target, port)
        print(f"   Banner: {banner}")
    except Exception as e:
        print(f"   Error: {e}")
    print()
    
    # Example 2: Service Detection
    print("2. Service Detection")
    print(f"   Detecting service on {target}:{port}...")
    try:
        service = await detection.detect_service(target, port)
        print(f"   Service: {service['name']}")
        print(f"   Version: {service['version']}")
        print(f"   Confidence: {service['confidence']}")
    except Exception as e:
        print(f"   Error: {e}")
    print()
    
    # Example 3: Basic OS Detection
    print("3. Basic OS Detection")
    print(f"   Detecting OS on {target}...")
    try:
        os_info = await detection.detect_os(target, port)
        print(f"   OS: {os_info['os_name']}")
        print(f"   Family: {os_info['os_family']}")
        print(f"   Confidence: {os_info['confidence']}")
    except Exception as e:
        print(f"   Error: {e}")
    print()
    
    # Example 4: Advanced OS Fingerprinting
    print("4. Advanced OS Fingerprinting")
    os_engine = OsFingerprintEngine()
    
    print(f"   Database: {os_engine.get_database_info()['signature_count']} signatures loaded")
    print(f"   Fingerprinting {target}...")
    try:
        fingerprint = await os_engine.fingerprint(target, port)
        print(f"   Detection time: {fingerprint['detection_time_ms']}ms")
        print(f"   Techniques used:")
        if fingerprint['has_tcp']:
            print("     ✓ TCP/IP Stack Fingerprinting")
        if fingerprint['has_icmp']:
            print("     ✓ ICMP-Based Fingerprinting")
        if fingerprint['has_clock_skew']:
            print("     ✓ Clock Skew Analysis")
            if 'clock_skew' in fingerprint:
                clock = fingerprint['clock_skew']
                if 'skew_ppm' in clock:
                    print(f"       Clock skew: {clock['skew_ppm']:.2f} ppm")
        
        # Match against database
        print("\n   Matching against OS database...")
        matches = await os_engine.detect_os(target, port)
        if matches:
            print(f"   Top matches:")
            for i, match in enumerate(matches[:3], 1):
                print(f"     {i}. {match['os_name']} - {match['confidence_score']*100:.1f}%")
    except Exception as e:
        print(f"   Error: {e}")
    
    print("\n=== Example Complete ===")

if __name__ == "__main__":
    asyncio.run(main())

