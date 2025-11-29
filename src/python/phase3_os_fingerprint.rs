//! Phase 3: OS Fingerprinting Python Bindings
//!
//! This module provides Python bindings for:
//! - Comprehensive OS fingerprinting
//! - TCP/IP stack analysis
//! - ICMP fingerprinting
//! - Active probes
//! - Clock skew analysis
//! - Passive fingerprinting

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3_asyncio::tokio::future_into_py;
use std::net::IpAddr;
use std::sync::Arc;

use crate::os_fingerprint::{OsFingerprintEngine, OsFingerprintDatabase};

/// Python wrapper for OS Fingerprinting Engine
#[pyclass]
pub struct PyOsFingerprintEngine {
    engine: Arc<OsFingerprintEngine>,
}

#[pymethods]
impl PyOsFingerprintEngine {
    /// Create a new OS fingerprinting engine
    /// 
    /// Example:
    ///     >>> engine = PyOsFingerprintEngine()
    #[new]
    fn new() -> PyResult<Self> {
        let engine = OsFingerprintEngine::new();
        Ok(PyOsFingerprintEngine { 
            engine: Arc::new(engine),
        })
    }

    /// Fingerprint a target OS
    /// 
    /// Args:
    ///     target (str): Target IP address
    ///     open_port (int): Known open port
    ///     closed_port (int, optional): Known closed port
    ///     use_active_probes (bool, optional): Use active probes (intrusive)
    /// 
    /// Returns:
    ///     dict: Complete OS fingerprint data
    /// 
    /// Example:
    ///     >>> fp = await engine.fingerprint("192.168.1.1", 22)
    ///     >>> print(f"Detection time: {fp['detection_time_ms']}ms")
    #[pyo3(signature = (target, open_port, closed_port=None, use_active_probes=false))]
    fn fingerprint<'a>(
        &self,
        py: Python<'a>,
        target: String,
        open_port: u16,
        closed_port: Option<u16>,
        use_active_probes: bool,
    ) -> PyResult<&'a PyAny> {
        let engine = Arc::clone(&self.engine);
        let target_ip: IpAddr = target.parse()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid IP: {}", e)))?;

        future_into_py(py, async move {
            match engine.fingerprint(target_ip, open_port, closed_port, use_active_probes).await {
                Ok(fingerprint) => {
                    Python::with_gil(|py| {
                        let dict = PyDict::new(py);
                        dict.set_item("target", fingerprint.target.to_string())?;
                        dict.set_item("detection_time_ms", fingerprint.detection_time_ms)?;
                        dict.set_item("has_tcp", fingerprint.tcp_fingerprint.is_some())?;
                        dict.set_item("has_icmp", fingerprint.icmp_fingerprint.is_some())?;
                        dict.set_item("has_udp", fingerprint.udp_fingerprint.is_some())?;
                        dict.set_item("has_protocol_hints", fingerprint.protocol_hints.is_some())?;
                        dict.set_item("has_clock_skew", fingerprint.clock_skew.is_some())?;
                        dict.set_item("has_passive", fingerprint.passive_fingerprint.is_some())?;
                        dict.set_item("has_active_probes", fingerprint.active_probes.is_some())?;
                        
                        // Add clock skew data if available
                        if let Some(ref clock) = fingerprint.clock_skew {
                            let clock_dict = PyDict::new(py);
                            if let Some(skew) = clock.skew_ppm {
                                clock_dict.set_item("skew_ppm", skew)?;
                            }
                            if let Some(freq) = clock.clock_frequency_hz {
                                clock_dict.set_item("frequency_hz", freq)?;
                            }
                            clock_dict.set_item("confidence", clock.confidence)?;
                            
                            let hints_list = PyList::empty(py);
                            for hint in &clock.os_hints {
                                hints_list.append(hint)?;
                            }
                            clock_dict.set_item("os_hints", hints_list)?;
                            
                            dict.set_item("clock_skew", clock_dict)?;
                        }
                        
                        Ok::<Py<PyDict>, PyErr>(dict.into())
                    })
                }
                Err(e) => {
                    Python::with_gil(|_| Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Fingerprinting failed: {}", e))))
                }
            }
        })
    }

    /// Detect OS and match against database
    /// 
    /// Args:
    ///     target (str): Target IP address
    ///     open_port (int): Known open port
    ///     closed_port (int, optional): Known closed port
    ///     use_active_probes (bool, optional): Use active probes
    /// 
    /// Returns:
    ///     list[dict]: List of OS matches with confidence scores
    /// 
    /// Example:
    ///     >>> matches = await engine.detect_os("192.168.1.1", 22)
    ///     >>> for match in matches:
    ///     ...     print(f"{match['os_name']}: {match['confidence']}%")
    #[pyo3(signature = (target, open_port, closed_port=None, use_active_probes=false))]
    fn detect_os<'a>(
        &self,
        py: Python<'a>,
        target: String,
        open_port: u16,
        closed_port: Option<u16>,
        use_active_probes: bool,
    ) -> PyResult<&'a PyAny> {
        let engine = Arc::clone(&self.engine);
        let target_ip: IpAddr = target.parse()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid IP: {}", e)))?;

        future_into_py(py, async move {
            match engine.detect_os(target_ip, open_port, closed_port, use_active_probes).await {
                Ok(matches) => {
                    Python::with_gil(|py| {
                        let results = PyList::empty(py);
                        
                        for m in matches {
                            let match_dict = PyDict::new(py);
                            match_dict.set_item("os_name", m.os_name)?;
                            match_dict.set_item("os_version", m.os_version)?;
                            match_dict.set_item("os_family", format!("{:?}", m.os_family))?;
                            match_dict.set_item("confidence", format!("{:?}", m.confidence))?;
                            match_dict.set_item("confidence_score", m.confidence_score)?;
                            
                            let features_list = PyList::empty(py);
                            for feature in &m.matching_features {
                                features_list.append(feature)?;
                            }
                            match_dict.set_item("matching_features", features_list)?;
                            
                            results.append(match_dict)?;
                        }
                        
                        Ok::<Py<PyList>, PyErr>(results.into())
                    })
                }
                Err(e) => {
                    Python::with_gil(|_| Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("OS detection failed: {}", e))))
                }
            }
        })
    }

    /// Get database statistics
    /// 
    /// Returns:
    ///     dict: Database information
    fn get_database_info(&self) -> PyResult<Py<PyDict>> {
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            // Create a temporary database to get count
            let db = OsFingerprintDatabase::new();
            dict.set_item("signature_count", db.signatures().len())?;
            Ok(dict.into())
        })
    }

    fn __repr__(&self) -> String {
        let db = OsFingerprintDatabase::new();
        format!(
            "PyOsFingerprintEngine(signatures={})",
            db.signatures().len()
        )
    }
}

/// Python wrapper for OS match result
#[pyclass]
#[derive(Clone)]
pub struct PyOsMatchResult {
    #[pyo3(get)]
    os_name: String,
    #[pyo3(get)]
    os_version: Option<String>,
    #[pyo3(get)]
    confidence_score: f64,
    #[pyo3(get)]
    matching_features: Vec<String>,
}

#[pymethods]
impl PyOsMatchResult {
    fn __repr__(&self) -> String {
        format!(
            "OsMatchResult(os='{}', confidence={:.1}%)",
            self.os_name,
            self.confidence_score * 100.0
        )
    }

    fn to_dict(&self) -> PyResult<Py<PyDict>> {
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("os_name", &self.os_name)?;
            dict.set_item("os_version", &self.os_version)?;
            dict.set_item("confidence_score", self.confidence_score)?;
            dict.set_item("matching_features", &self.matching_features)?;
            Ok(dict.into())
        })
    }
}

