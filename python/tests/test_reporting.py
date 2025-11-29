"""
Tests for Reporting bindings
"""

import pytest
from nrmap import ReportEngine, ReportFormat, generate_report

def test_report_engine_creation():
    """Test ReportEngine creation"""
    engine = ReportEngine()
    assert engine is not None

def test_available_formats():
    """Test available report formats"""
    formats = ReportFormat.available_formats()
    
    assert isinstance(formats, list)
    assert "json" in formats
    assert "yaml" in formats
    assert "html" in formats
    assert "table" in formats

def test_generate_report():
    """Test report generation"""
    engine = ReportEngine()
    
    scan_data = {
        "target": "127.0.0.1",
        "tcp_results": [{"port": 22, "open": True}]
    }
    
    # JSON format
    report = engine.generate_report(scan_data, "json")
    assert isinstance(report, str)
    assert len(report) > 0
    
    # YAML format
    report = engine.generate_report(scan_data, "yaml")
    assert isinstance(report, str)

def test_generate_report_high_level():
    """Test high-level generate_report function"""
    scan_data = {
        "target": "192.168.1.1",
        "tcp_results": []
    }
    
    report = generate_report(scan_data, "json")
    assert isinstance(report, str)

def test_report_format_creation():
    """Test ReportFormat creation"""
    fmt = ReportFormat("json")
    assert fmt is not None
    repr_str = repr(fmt)
    assert "ReportFormat" in repr_str
    assert "json" in repr_str

def test_report_engine_repr():
    """Test ReportEngine __repr__"""
    engine = ReportEngine()
    repr_str = repr(engine)
    assert "PyReportEngine" in repr_str

