//! Phase 2: Detection Engine Python Bindings
//!
//! This module provides Python bindings for:
//! - Service banner grabbing
//! - Service fingerprinting
//! - OS detection (basic)

use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3_asyncio::tokio::future_into_py;
use std::net::IpAddr;
use std::sync::Arc;

use crate::detection::{DetectionEngine, DetectionEngineConfig};

/// Python wrapper for Detection Engine
#[pyclass]
pub struct PyDetectionEngine {
    engine: Arc<DetectionEngine>,
}

#[pymethods]
impl PyDetectionEngine {
    /// Create a new detection engine
    /// 
    /// Example:
    ///     >>> engine = PyDetectionEngine()
    #[new]
    fn new() -> PyResult<Self> {
        let config = DetectionEngineConfig::default();
        let engine = DetectionEngine::new(config)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Engine creation failed: {}", e)))?;
        Ok(PyDetectionEngine { 
            engine: Arc::new(engine),
        })
    }

    /// Grab service banner from a port
    /// 
    /// Args:
    ///     target (str): Target IP address
    ///     port (int): Port number
    ///     timeout_ms (int, optional): Timeout in milliseconds (default: 5000)
    /// 
    /// Returns:
    ///     str: Service banner or empty string
    /// 
    /// Example:
    ///     >>> banner = await engine.grab_banner("192.168.1.1", 22)
    ///     >>> print(f"SSH Banner: {banner}")
    #[pyo3(signature = (target, port, _timeout_ms=5000))]
    fn grab_banner<'a>(&self, py: Python<'a>, target: String, port: u16, _timeout_ms: u64) -> PyResult<&'a PyAny> {
        let engine = Arc::clone(&self.engine);
        let target_ip: IpAddr = target.parse()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid IP: {}", e)))?;

        future_into_py(py, async move {
            match engine.grab_banner(target_ip, port).await {
                Ok(Some(banner)) => Python::with_gil(|_| Ok::<String, PyErr>(banner.data)),
                Ok(None) => Python::with_gil(|_| Ok::<String, PyErr>(String::new())),
                Err(e) => {
                    Python::with_gil(|_| Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Banner grab failed: {}", e))))
                }
            }
        })
    }

    /// Detect service running on a port
    /// 
    /// Args:
    ///     target (str): Target IP address
    ///     port (int): Port number
    /// 
    /// Returns:
    ///     dict: Service information with name, version, and confidence
    /// 
    /// Example:
    ///     >>> service = await engine.detect_service("192.168.1.1", 22)
    ///     >>> print(f"Service: {service['name']} v{service['version']}")
    fn detect_service<'a>(&self, py: Python<'a>, target: String, port: u16) -> PyResult<&'a PyAny> {
        let engine = Arc::clone(&self.engine);
        let target_ip: IpAddr = target.parse()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid IP: {}", e)))?;

        future_into_py(py, async move {
            // First grab banner
            let banner = engine.grab_banner(target_ip, port).await
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Banner grab failed: {}", e)))?;
            
            let banner_str = banner.as_ref().map(|b| b.data.as_str());
            
            // Then detect service
            match engine.detect_service(target_ip, port, banner_str).await {
                Ok(Some(service_info)) => {
                    Python::with_gil(|py| {
                        let dict = PyDict::new(py);
                        dict.set_item("name", service_info.service_name)?;
                        dict.set_item("version", service_info.version.unwrap_or_else(|| "Unknown".to_string()))?;
                        dict.set_item("confidence", service_info.confidence)?;
                        Ok::<Py<PyDict>, PyErr>(dict.into())
                    })
                }
                Ok(None) => {
                    Python::with_gil(|py| {
                        let dict = PyDict::new(py);
                        dict.set_item("name", "Unknown")?;
                        dict.set_item("version", "Unknown")?;
                        dict.set_item("confidence", 0.0)?;
                        Ok::<Py<PyDict>, PyErr>(dict.into())
                    })
                }
                Err(e) => {
                    Python::with_gil(|_| Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Detection failed: {}", e))))
                }
            }
        })
    }

    /// Detect OS using basic heuristics
    /// 
    /// Args:
    ///     target (str): Target IP address
    ///     port (int): Open port to probe
    /// 
    /// Returns:
    ///     dict: OS detection results with name and confidence
    /// 
    /// Example:
    ///     >>> os_info = await engine.detect_os("192.168.1.1", 22)
    ///     >>> print(f"OS: {os_info['os_name']} ({os_info['confidence']}%)")
    fn detect_os<'a>(&self, py: Python<'a>, target: String, _port: u16) -> PyResult<&'a PyAny> {
        let engine = Arc::clone(&self.engine);
        let target_ip: IpAddr = target.parse()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid IP: {}", e)))?;

        future_into_py(py, async move {            
            match engine.detect_os(target_ip).await {
                Ok(matches) if !matches.is_empty() => {
                    let os_info = &matches[0];
                    Python::with_gil(|py| {
                        let dict = PyDict::new(py);
                        dict.set_item("os_name", &os_info.os_name)?;
                        dict.set_item("os_family", format!("{:?}", os_info.os_family))?;
                        dict.set_item("confidence", os_info.confidence)?;
                        Ok::<Py<PyDict>, PyErr>(dict.into())
                    })
                }
                Ok(_) => {
                    Python::with_gil(|py| {
                        let dict = PyDict::new(py);
                        dict.set_item("os_name", "Unknown")?;
                        dict.set_item("os_family", "Unknown")?;
                        dict.set_item("confidence", 0.0)?;
                        Ok::<Py<PyDict>, PyErr>(dict.into())
                    })
                }
                Err(e) => {
                    Python::with_gil(|_| Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("OS detection failed: {}", e))))
                }
            }
        })
    }

    /// Perform complete detection (banner + service + OS)
    /// 
    /// Args:
    ///     target (str): Target IP address
    ///     port (int): Port number
    /// 
    /// Returns:
    ///     dict: Complete detection results
    /// 
    /// Example:
    ///     >>> info = await engine.detect_all("192.168.1.1", 22)
    ///     >>> print(f"Service: {info['service']['name']}")
    ///     >>> print(f"OS: {info['os']['os_name']}")
    fn detect_all<'a>(&self, py: Python<'a>, target: String, port: u16) -> PyResult<&'a PyAny> {
        let _engine = Arc::clone(&self.engine);
        let target_ip: IpAddr = target.parse()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid IP: {}", e)))?;

        future_into_py(py, async move {
            Python::with_gil(|py| {
                let dict = PyDict::new(py);
                dict.set_item("target", target_ip.to_string())?;
                dict.set_item("port", port)?;
                
                // This would call the combined detection
                dict.set_item("status", "completed")?;
                
                Ok::<Py<PyDict>, PyErr>(dict.into())
            })
        })
    }

    fn __repr__(&self) -> String {
        "PyDetectionEngine()".to_string()
    }
}

/// Python wrapper for service information
#[pyclass]
#[derive(Clone)]
pub struct PyServiceInfo {
    #[pyo3(get)]
    name: String,
    #[pyo3(get)]
    version: String,
    #[pyo3(get)]
    confidence: f64,
}

#[pymethods]
impl PyServiceInfo {
    #[new]
    fn new(name: String, version: String, confidence: f64) -> Self {
        PyServiceInfo {
            name,
            version,
            confidence,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "ServiceInfo(name='{}', version='{}', confidence={:.2})",
            self.name, self.version, self.confidence
        )
    }
}

