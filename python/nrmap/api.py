"""
High-level Python API for NrMAP

Provides convenient functions for common scanning tasks.
"""

import asyncio
from typing import List, Dict, Optional, Union
from ._nrmap_rs import (
    PyScanner as Scanner,
    PyDetectionEngine as DetectionEngine,
    PyOsFingerprintEngine as OsFingerprintEngine,
    PyReportEngine as ReportEngine,
)


async def quick_scan(
    target: str,
    ports: List[int],
    scan_type: str = "tcp"
) -> List[int]:
    """
    Quick scan to find open ports
    
    Args:
        target: Target IP address or hostname
        ports: List of ports to scan
        scan_type: Scan type ("tcp", "syn", or "udp")
    
    Returns:
        List of open ports
    
    Example:
        >>> open_ports = await quick_scan("192.168.1.1", [22, 80, 443])
        >>> print(f"Open ports: {open_ports}")
    """
    scanner = Scanner()
    result = await scanner.quick_scan(target, ports)
    return result


async def scan_network(
    target: str,
    ports: List[int],
    scan_types: Optional[List[str]] = None,
    detect_services: bool = False,
    detect_os: bool = False
) -> Dict:
    """
    Comprehensive network scan with optional service and OS detection
    
    Args:
        target: Target IP address or hostname
        ports: List of ports to scan
        scan_types: List of scan types (default: ["tcp"])
        detect_services: Enable service detection
        detect_os: Enable OS detection
    
    Returns:
        Complete scan results dictionary
    
    Example:
        >>> result = await scan_network(
        ...     "192.168.1.1",
        ...     [22, 80, 443],
        ...     detect_services=True,
        ...     detect_os=True
        ... )
        >>> print(f"OS: {result.get('os', {}).get('os_name', 'Unknown')}")
    """
    scanner = Scanner()
    scan_types = scan_types or ["tcp"]
    
    # Perform base scan
    result = await scanner.scan(target, ports, scan_types)
    
    # Add service detection if requested
    if detect_services:
        detection_engine = DetectionEngine()
        services = {}
        for port_info in result.get("tcp_results", []):
            if port_info["open"]:
                port = port_info["port"]
                try:
                    service = await detection_engine.detect_service(target, port)
                    services[port] = service
                except Exception as e:
                    services[port] = {"error": str(e)}
        result["services"] = services
    
    # Add OS detection if requested
    if detect_os:
        os_engine = OsFingerprintEngine()
        # Find first open port
        open_port = None
        for port_info in result.get("tcp_results", []):
            if port_info["open"]:
                open_port = port_info["port"]
                break
        
        if open_port:
            try:
                os_matches = await os_engine.detect_os(target, open_port)
                result["os"] = os_matches[0] if os_matches else None
            except Exception as e:
                result["os"] = {"error": str(e)}
    
    return result


def detect_os(target: str, open_port: int, use_active_probes: bool = False) -> Dict:
    """
    Detect operating system (blocking call)
    
    Args:
        target: Target IP address
        open_port: Known open port
        use_active_probes: Use active probes (intrusive)
    
    Returns:
        OS detection results
    
    Example:
        >>> os_info = detect_os("192.168.1.1", 22)
        >>> print(f"OS: {os_info['os_name']}")
    """
    async def _detect():
        engine = OsFingerprintEngine()
        matches = await engine.detect_os(target, open_port, None, use_active_probes)
        return matches[0] if matches else {"os_name": "Unknown", "confidence_score": 0.0}
    
    return asyncio.run(_detect())


async def fingerprint_os(
    target: str,
    open_port: int,
    closed_port: Optional[int] = None,
    use_active_probes: bool = False
) -> Dict:
    """
    Comprehensive OS fingerprinting
    
    Args:
        target: Target IP address
        open_port: Known open port
        closed_port: Known closed port (for advanced probes)
        use_active_probes: Use active probes (very intrusive!)
    
    Returns:
        Complete OS fingerprint data
    
    Example:
        >>> fingerprint = await fingerprint_os("192.168.1.1", 22)
        >>> print(f"Detection techniques used: {fingerprint.get('has_tcp', False)}")
    """
    engine = OsFingerprintEngine()
    return await engine.fingerprint(target, open_port, closed_port, use_active_probes)


def generate_report(
    scan_data: Dict,
    format: str = "json",
    output_path: Optional[str] = None
) -> str:
    """
    Generate a scan report
    
    Args:
        scan_data: Scan results dictionary
        format: Output format ("json", "yaml", "html", "table")
        output_path: Optional file path to save report
    
    Returns:
        Formatted report as string
    
    Example:
        >>> report = generate_report(scan_results, "json", "report.json")
        >>> print(report[:100])
    """
    engine = ReportEngine()
    return engine.generate_report(scan_data, format, output_path)

