//! Python Bindings Module
//!
//! This module provides Python bindings for NrMAP using PyO3.
//! Organized in phases for comprehensive coverage.

#[cfg(feature = "python")]
pub mod phase1_scanner;

#[cfg(feature = "python")]
pub mod phase2_detection;

#[cfg(feature = "python")]
pub mod phase3_os_fingerprint;

#[cfg(feature = "python")]
pub mod phase4_reporting;

#[cfg(feature = "python")]
use pyo3::prelude::*;

/// Initialize the Python module
#[cfg(feature = "python")]
#[pymodule]
fn nrmap_rs(_py: Python, m: &PyModule) -> PyResult<()> {
    // Phase 1: Core Scanner
    m.add_class::<phase1_scanner::PyScanner>()?;
    m.add_class::<phase1_scanner::PyHostStatus>()?;
    m.add_class::<phase1_scanner::PyScanResult>()?;
    
    // Phase 2: Detection Engine
    m.add_class::<phase2_detection::PyDetectionEngine>()?;
    m.add_class::<phase2_detection::PyServiceInfo>()?;
    
    // Phase 3: OS Fingerprinting
    m.add_class::<phase3_os_fingerprint::PyOsFingerprintEngine>()?;
    m.add_class::<phase3_os_fingerprint::PyOsMatchResult>()?;
    
    // Phase 4: Reporting
    m.add_class::<phase4_reporting::PyReportEngine>()?;
    m.add_class::<phase4_reporting::PyReportFormat>()?;
    
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    
    Ok(())
}

