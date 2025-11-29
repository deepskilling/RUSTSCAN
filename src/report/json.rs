/// JSON report generator
/// 
/// This module generates JSON format reports for scan results.

use crate::error::{ScanError, ScanResult};
use crate::report::ScanReport;
use tracing::debug;

/// JSON report generator
pub struct JsonReportGenerator;

impl JsonReportGenerator {
    /// Create a new JSON report generator
    pub fn new() -> Self {
        Self
    }

    /// Generate a JSON report
    /// 
    /// # Arguments
    /// * `report` - The scan report to format
    /// * `pretty` - Whether to use pretty printing
    pub fn generate(&self, report: &ScanReport, pretty: bool) -> ScanResult<String> {
        debug!("Generating JSON report (pretty: {})", pretty);
        
        let result = if pretty {
            serde_json::to_string_pretty(report)
        } else {
            serde_json::to_string(report)
        };

        result.map_err(|e| ScanError::OutputError {
            message: format!("Failed to serialize report to JSON: {}", e),
        })
    }
}

impl Default for JsonReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{ReportBuilder, ScanParameters};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_json_generator_creation() {
        let generator = JsonReportGenerator::new();
        assert!(std::mem::size_of_val(&generator) >= 0);
    }

    #[test]
    fn test_generate_json() {
        let generator = JsonReportGenerator::new();
        
        let params = ScanParameters {
            targets: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
            ports: vec![80, 443],
            scan_types: vec!["TcpConnect".to_string()],
            timeout_ms: 5000,
            concurrent_scans: 100,
        };

        let report = ReportBuilder::new("test-1".to_string())
            .with_parameters(params)
            .complete()
            .build()
            .unwrap();

        let json = generator.generate(&report, false);
        assert!(json.is_ok());
        
        let json_str = json.unwrap();
        assert!(json_str.contains("test-1"));
        assert!(json_str.contains("metadata"));
    }

    #[test]
    fn test_generate_pretty_json() {
        let generator = JsonReportGenerator::new();
        
        let report = ReportBuilder::new("test-2".to_string())
            .complete()
            .build()
            .unwrap();

        let json = generator.generate(&report, true);
        assert!(json.is_ok());
        
        let json_str = json.unwrap();
        assert!(json_str.contains("\n")); // Pretty print includes newlines
        assert!(json_str.contains("  ")); // Pretty print includes indentation
    }
}

