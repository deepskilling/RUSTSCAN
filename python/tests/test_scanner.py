"""
Tests for Scanner bindings
"""

import pytest
from nrmap import Scanner, quick_scan

@pytest.mark.asyncio
async def test_scanner_creation():
    """Test Scanner creation"""
    scanner = Scanner()
    assert scanner is not None
    stats = scanner.get_stats()
    assert "version" in stats
    assert "scanner_type" in stats

@pytest.mark.asyncio
async def test_quick_scan():
    """Test quick_scan function"""
    # Test localhost (should be safe)
    result = await quick_scan("127.0.0.1", [22, 80, 443])
    assert isinstance(result, list)
    assert all(isinstance(port, int) for port in result)

@pytest.mark.asyncio
async def test_scanner_scan():
    """Test Scanner.scan method"""
    scanner = Scanner()
    result = await scanner.scan("127.0.0.1", [22, 80], ["tcp"])
    
    assert "target" in result
    assert "host_status" in result
    assert "scan_duration_ms" in result
    assert "tcp_results" in result
    
    assert result["target"] == "127.0.0.1"
    assert isinstance(result["scan_duration_ms"], int)
    assert isinstance(result["tcp_results"], list)

def test_scanner_repr():
    """Test Scanner __repr__"""
    scanner = Scanner()
    repr_str = repr(scanner)
    assert "PyScanner" in repr_str
    assert "version" in repr_str

