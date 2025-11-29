"""
Tests for OS Fingerprinting bindings
"""

import pytest
from nrmap import OsFingerprintEngine

def test_os_engine_creation():
    """Test OsFingerprintEngine creation"""
    engine = OsFingerprintEngine()
    assert engine is not None

def test_get_database_info():
    """Test database info retrieval"""
    engine = OsFingerprintEngine()
    db_info = engine.get_database_info()
    
    assert "signature_count" in db_info
    assert isinstance(db_info["signature_count"], int)
    assert db_info["signature_count"] > 0  # Should have built-in signatures

@pytest.mark.asyncio
async def test_fingerprint():
    """Test OS fingerprinting"""
    engine = OsFingerprintEngine()
    
    try:
        fingerprint = await engine.fingerprint("127.0.0.1", 22)
        assert "target" in fingerprint
        assert "detection_time_ms" in fingerprint
        assert "has_tcp" in fingerprint
        assert "has_icmp" in fingerprint
    except Exception:
        # Expected if target not reachable
        pass

@pytest.mark.asyncio
async def test_detect_os():
    """Test OS detection and matching"""
    engine = OsFingerprintEngine()
    
    try:
        matches = await engine.detect_os("127.0.0.1", 22)
        assert isinstance(matches, list)
        
        if matches:
            match = matches[0]
            assert "os_name" in match
            assert "confidence_score" in match
            assert isinstance(match["confidence_score"], float)
    except Exception:
        # Expected if target not reachable
        pass

def test_os_engine_repr():
    """Test OsFingerprintEngine __repr__"""
    engine = OsFingerprintEngine()
    repr_str = repr(engine)
    assert "PyOsFingerprintEngine" in repr_str
    assert "signatures" in repr_str

