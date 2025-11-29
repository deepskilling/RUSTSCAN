//! Phase 4: Reporting Python Bindings
//!
//! This module provides Python bindings for:
//! - Report generation (JSON, YAML, HTML, Table)
//! - Report formatting
//! - Output customization

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::report::{ReportEngine, ReportFormat};

/// Python wrapper for Report Engine
#[pyclass]
pub struct PyReportEngine {
    engine: ReportEngine,
}

#[pymethods]
impl PyReportEngine {
    /// Create a new report engine
    /// 
    /// Example:
    ///     >>> engine = PyReportEngine()
    #[new]
    fn new() -> PyResult<Self> {
        let engine = ReportEngine::new();
        Ok(PyReportEngine { engine })
    }

    /// Generate report in specified format
    /// 
    /// Args:
    ///     scan_data (dict): Scan results data
    ///     format (str): Output format ("json", "yaml", "html", "table")
    ///     output_path (str, optional): File path to save report
    /// 
    /// Returns:
    ///     str: Generated report as string
    /// 
    /// Example:
    ///     >>> report = engine.generate_report(scan_data, "json")
    ///     >>> print(report)
    #[pyo3(signature = (_scan_data, format, output_path=None))]
    fn generate_report(
        &self,
        _scan_data: &PyDict,
        format: String,
        output_path: Option<String>,
    ) -> PyResult<String> {
        let _output_format = match format.as_str() {
            "json" => ReportFormat::Json,
            "json_pretty" => ReportFormat::JsonPretty,
            "yaml" => ReportFormat::Yaml,
            "html" => ReportFormat::Html,
            "table" => ReportFormat::Table,
            _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid format: {}. Use: json, yaml, html, or table", format)
            )),
        };

        // In a real implementation, would convert scan_data to ScanReport
        // For now, return a simple formatted string
        let report = format!("Report generated in {} format", format);

        if let Some(path) = output_path {
            std::fs::write(&path, &report)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to write report: {}", e)))?;
        }

        Ok(report)
    }

    /// Create a report builder for customization
    /// 
    /// Returns:
    ///     PyReportBuilder: Builder for customizing reports
    fn builder(&self) -> PyResult<PyReportBuilder> {
        Ok(PyReportBuilder::new())
    }

    fn __repr__(&self) -> String {
        "PyReportEngine()".to_string()
    }
}

/// Python wrapper for Report Format
#[pyclass]
#[derive(Clone)]
pub struct PyReportFormat {
    #[pyo3(get)]
    name: String,
}

#[pymethods]
impl PyReportFormat {
    #[new]
    fn new(name: String) -> Self {
        PyReportFormat { name }
    }

    /// Get available formats
    /// 
    /// Returns:
    ///     list[str]: List of supported formats
    #[staticmethod]
    fn available_formats() -> Vec<String> {
        vec![
            "json".to_string(),
            "json_pretty".to_string(),
            "yaml".to_string(),
            "html".to_string(),
            "table".to_string(),
        ]
    }

    fn __repr__(&self) -> String {
        format!("ReportFormat({})", self.name)
    }
}

/// Python wrapper for Report Builder
#[pyclass]
pub struct PyReportBuilder {
    title: Option<String>,
    include_stats: bool,
    include_details: bool,
}

#[pymethods]
impl PyReportBuilder {
    #[new]
    fn new() -> Self {
        PyReportBuilder {
            title: None,
            include_stats: true,
            include_details: true,
        }
    }

    /// Set report title
    fn with_title(&mut self, title: String) -> PyResult<()> {
        self.title = Some(title);
        Ok(())
    }

    /// Set whether to include statistics
    fn with_stats(&mut self, include: bool) -> PyResult<()> {
        self.include_stats = include;
        Ok(())
    }

    /// Set whether to include detailed results
    fn with_details(&mut self, include: bool) -> PyResult<()> {
        self.include_details = include;
        Ok(())
    }

    fn __repr__(&self) -> String {
        format!(
            "ReportBuilder(title={:?}, stats={}, details={})",
            self.title, self.include_stats, self.include_details
        )
    }
}

