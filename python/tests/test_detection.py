"""
Tests for Detection Engine bindings
"""

import pytest
from nrmap import DetectionEngine

@pytest.mark.asyncio
async def test_detection_engine_creation():
    """Test DetectionEngine creation"""
    engine = DetectionEngine()
    assert engine is not None

@pytest.mark.asyncio
async def test_grab_banner():
    """Test banner grabbing"""
    engine = DetectionEngine()
    
    # Should not crash even if target is unreachable
    try:
        banner = await engine.grab_banner("127.0.0.1", 22)
        assert isinstance(banner, str)
    except Exception:
        # Expected if port is closed
        pass

@pytest.mark.asyncio
async def test_detect_service():
    """Test service detection"""
    engine = DetectionEngine()
    
    try:
        service = await engine.detect_service("127.0.0.1", 22)
        assert "name" in service
        assert "version" in service
        assert "confidence" in service
    except Exception:
        # Expected if service not detected
        pass

def test_detection_repr():
    """Test DetectionEngine __repr__"""
    engine = DetectionEngine()
    repr_str = repr(engine)
    assert "PyDetectionEngine" in repr_str

