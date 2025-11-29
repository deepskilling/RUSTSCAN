"""
NrMAP - Network Reconnaissance and Mapping Platform
Python bindings for the high-performance Rust-based network scanner

This package provides Python bindings for NrMAP, a comprehensive network
reconnaissance tool built in Rust.
"""

__version__ = "0.1.0"

try:
    from ._nrmap_rs import (
        # Phase 1: Core Scanner
        PyScanner as Scanner,
        PyHostStatus as HostStatus,
        PyScanResult as ScanResult,
        
        # Phase 2: Detection Engine
        PyDetectionEngine as DetectionEngine,
        PyServiceInfo as ServiceInfo,
        
        # Phase 3: OS Fingerprinting
        PyOsFingerprintEngine as OsFingerprintEngine,
        PyOsMatchResult as OsMatchResult,
        
        # Phase 4: Reporting
        PyReportEngine as ReportEngine,
        PyReportFormat as ReportFormat,
    )
except ImportError as e:
    raise ImportError(
        f"Failed to import Rust extension module: {e}\n"
        "Please ensure the package is properly installed with: pip install -e ."
    )

# High-level API
from .api import (
    quick_scan,
    scan_network,
    detect_os,
    fingerprint_os,
    generate_report,
)

__all__ = [
    # Core classes
    "Scanner",
    "HostStatus",
    "ScanResult",
    "DetectionEngine",
    "ServiceInfo",
    "OsFingerprintEngine",
    "OsMatchResult",
    "ReportEngine",
    "ReportFormat",
    
    # High-level API
    "quick_scan",
    "scan_network",
    "detect_os",
    "fingerprint_os",
    "generate_report",
    
    # Version
    "__version__",
]

