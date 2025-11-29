//! Phase 1: Core Scanner Python Bindings
//!
//! This module provides Python bindings for:
//! - Host discovery
//! - TCP connect scan
//! - TCP SYN scan
//! - UDP scan
//! - Adaptive throttling

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3_asyncio::tokio::future_into_py;
use std::net::IpAddr;
use std::sync::Arc;

use crate::config::AppConfig;
use crate::scanner::{Scanner, ScanType};
use crate::scanner::host_discovery::HostStatus;

/// Python wrapper for Scanner
#[pyclass]
pub struct PyScanner {
    scanner: Arc<Scanner>,
}

#[pymethods]
impl PyScanner {
    /// Create a new scanner
    /// 
    /// Args:
    ///     config_path (str, optional): Path to config.toml file
    /// 
    /// Example:
    ///     >>> scanner = PyScanner()
    ///     >>> scanner = PyScanner("custom_config.toml")
    #[new]
    #[pyo3(signature = (config_path=None))]
    fn new(config_path: Option<String>) -> PyResult<Self> {
        let app_config = if let Some(path) = config_path {
            AppConfig::from_file(&path)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Config error: {}", e)))?
        } else {
            AppConfig::default()
        };

        let scanner = Scanner::new(app_config.scanner);
        
        Ok(PyScanner { 
            scanner: Arc::new(scanner),
        })
    }

    /// Scan a target with specified scan types
    /// 
    /// Args:
    ///     target (str): Target IP address or hostname
    ///     ports (list[int]): List of ports to scan
    ///     scan_types (list[str], optional): Scan types ["tcp", "syn", "udp"]
    /// 
    /// Returns:
    ///     dict: Scan results with host status and port information
    /// 
    /// Example:
    ///     >>> result = scanner.scan("192.168.1.1", [22, 80, 443], ["tcp"])
    ///     >>> print(result["host_status"])
    #[pyo3(signature = (target, ports, scan_types=None))]
    fn scan<'a>(&self, py: Python<'a>, target: String, ports: Vec<u16>, scan_types: Option<Vec<String>>) -> PyResult<&'a PyAny> {
        let scanner = Arc::clone(&self.scanner);
        let target_ip: IpAddr = target.parse()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid IP: {}", e)))?;
        
        let scan_types_vec = if let Some(types) = scan_types {
            types.iter().map(|t| match t.as_str() {
                "tcp" => ScanType::TcpConnect,
                "syn" => ScanType::TcpSyn,
                "udp" => ScanType::Udp,
                _ => ScanType::TcpConnect,
            }).collect()
        } else {
            vec![ScanType::TcpConnect]
        };

        future_into_py(py, async move {
            let result = scanner.scan(target_ip, ports, scan_types_vec).await
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Scan failed: {}", e)))?;
            
            Python::with_gil(|py| {
                let dict = PyDict::new(py);
                dict.set_item("target", result.target.to_string())?;
                dict.set_item("host_status", format!("{:?}", result.host_status))?;
                dict.set_item("scan_duration_ms", result.scan_duration_ms)?;
                
                // TCP results
                let tcp_list = PyList::empty(py);
                for tcp_result in &result.tcp_results {
                    let tcp_dict = PyDict::new(py);
                    tcp_dict.set_item("port", tcp_result.port)?;
                    let is_open = matches!(tcp_result.status, crate::scanner::tcp_connect::PortStatus::Open);
                    tcp_dict.set_item("open", is_open)?;
                    tcp_dict.set_item("response_time_ms", tcp_result.response_time_ms)?;
                    tcp_list.append(tcp_dict)?;
                }
                dict.set_item("tcp_results", tcp_list)?;
                
                // SYN results
                let syn_list = PyList::empty(py);
                for syn_result in &result.syn_results {
                    let syn_dict = PyDict::new(py);
                    syn_dict.set_item("port", syn_result.port)?;
                    // Check status via string comparison
                    let is_open = format!("{:?}", syn_result.status).contains("Open");
                    syn_dict.set_item("open", is_open)?;
                    syn_dict.set_item("response_time_ms", syn_result.response_time_ms)?;
                    syn_list.append(syn_dict)?;
                }
                dict.set_item("syn_results", syn_list)?;
                
                // UDP results
                let udp_list = PyList::empty(py);
                for udp_result in &result.udp_results {
                    let udp_dict = PyDict::new(py);
                    udp_dict.set_item("port", udp_result.port)?;
                    // Check status via string comparison for now
                    let is_open = format!("{:?}", udp_result.status).contains("Open");
                    udp_dict.set_item("open", is_open)?;
                    udp_dict.set_item("response_received", udp_result.response_data.is_some())?;
                    udp_list.append(udp_dict)?;
                }
                dict.set_item("udp_results", udp_list)?;
                
                Ok::<Py<PyDict>, PyErr>(dict.into())
            })
        })
    }

    /// Quick TCP scan (convenience method)
    /// 
    /// Args:
    ///     target (str): Target IP address
    ///     ports (list[int]): List of ports to scan
    /// 
    /// Returns:
    ///     list[int]: List of open ports
    /// 
    /// Example:
    ///     >>> open_ports = scanner.quick_scan("192.168.1.1", [22, 80, 443])
    ///     >>> print(f"Open ports: {open_ports}")
    fn quick_scan<'a>(&self, py: Python<'a>, target: String, ports: Vec<u16>) -> PyResult<&'a PyAny> {
        let scanner = Arc::clone(&self.scanner);
        let target_ip: IpAddr = target.parse()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid IP: {}", e)))?;

        future_into_py(py, async move {
            let result = scanner.scan(target_ip, ports, vec![ScanType::TcpConnect]).await
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Scan failed: {}", e)))?;
            
            Python::with_gil(|py| {
                let open_ports = PyList::empty(py);
                for tcp_result in &result.tcp_results {
                    // Check status via string comparison
                    if format!("{:?}", tcp_result.status).contains("Open") {
                        open_ports.append(tcp_result.port)?;
                    }
                }
                Ok::<Py<PyList>, PyErr>(open_ports.into())
            })
        })
    }

    /// Discover live hosts in a range
    /// 
    /// Args:
    ///     targets (list[str]): List of target IPs
    /// 
    /// Returns:
    ///     list[str]: List of live hosts
    /// 
    /// Example:
    ///     >>> hosts = scanner.discover_hosts(["192.168.1.1", "192.168.1.2"])
    ///     >>> print(f"Live hosts: {hosts}")
    fn discover_hosts<'a>(&self, py: Python<'a>, targets: Vec<String>) -> PyResult<&'a PyAny> {
        let scanner = Arc::clone(&self.scanner);
        
        let target_ips: Vec<IpAddr> = targets.iter()
            .filter_map(|t| t.parse().ok())
            .collect();

        future_into_py(py, async move {
            let mut live_hosts = Vec::new();
            
            for target in target_ips {
                match scanner.scan(target, vec![], vec![]).await {
                    Ok(result) if matches!(result.host_status, HostStatus::Up) => {
                        live_hosts.push(target.to_string());
                    }
                    _ => {}
                }
            }
            
            Python::with_gil(|py| {
                let hosts_list = PyList::empty(py);
                for host in live_hosts {
                    hosts_list.append(host)?;
                }
                Ok::<Py<PyList>, PyErr>(hosts_list.into())
            })
        })
    }

    /// Get scanner statistics
    /// 
    /// Returns:
    ///     dict: Scanner statistics and configuration
    fn get_stats(&self) -> PyResult<Py<PyDict>> {
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("version", env!("CARGO_PKG_VERSION"))?;
            dict.set_item("scanner_type", "NrMAP")?;
            Ok(dict.into())
        })
    }

    fn __repr__(&self) -> String {
        format!("PyScanner(version={})", env!("CARGO_PKG_VERSION"))
    }
}

/// Python wrapper for HostStatus
#[pyclass]
#[derive(Clone)]
pub struct PyHostStatus {
    #[pyo3(get)]
    status: String,
}

#[pymethods]
impl PyHostStatus {
    #[new]
    fn new(status: String) -> Self {
        PyHostStatus { status }
    }

    fn is_up(&self) -> bool {
        self.status == "Up"
    }

    fn is_down(&self) -> bool {
        self.status == "Down"
    }

    fn __repr__(&self) -> String {
        format!("HostStatus({})", self.status)
    }
}

/// Python wrapper for scan results
#[pyclass]
#[derive(Clone)]
pub struct PyScanResult {
    #[pyo3(get)]
    target: String,
    #[pyo3(get)]
    open_ports: Vec<u16>,
    #[pyo3(get)]
    closed_ports: Vec<u16>,
    #[pyo3(get)]
    scan_duration_ms: u64,
}

#[pymethods]
impl PyScanResult {
    fn __repr__(&self) -> String {
        format!(
            "ScanResult(target={}, open_ports={}, duration={}ms)",
            self.target,
            self.open_ports.len(),
            self.scan_duration_ms
        )
    }

    fn to_dict(&self) -> PyResult<Py<PyDict>> {
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("target", &self.target)?;
            dict.set_item("open_ports", &self.open_ports)?;
            dict.set_item("closed_ports", &self.closed_ports)?;
            dict.set_item("scan_duration_ms", self.scan_duration_ms)?;
            Ok(dict.into())
        })
    }
}

