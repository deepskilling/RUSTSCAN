/// YAML report generator
/// 
/// This module generates YAML format reports for scan results.

use crate::error::{ScanError, ScanResult};
use crate::report::ScanReport;
use tracing::debug;

/// YAML report generator
pub struct YamlReportGenerator;

impl YamlReportGenerator {
    /// Create a new YAML report generator
    pub fn new() -> Self {
        Self
    }

    /// Generate a YAML report
    /// 
    /// # Arguments
    /// * `report` - The scan report to format
    pub fn generate(&self, report: &ScanReport) -> ScanResult<String> {
        debug!("Generating YAML report");
        
        serde_yaml::to_string(report).map_err(|e| ScanError::OutputError {
            message: format!("Failed to serialize report to YAML: {}", e),
        })
    }
}

impl Default for YamlReportGenerator {
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
    fn test_yaml_generator_creation() {
        let generator = YamlReportGenerator::new();
        assert!(std::mem::size_of_val(&generator) >= 0);
    }

    #[test]
    fn test_generate_yaml() {
        let generator = YamlReportGenerator::new();
        
        let params = ScanParameters {
            targets: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
            ports: vec![80, 443],
            scan_types: vec!["TcpConnect".to_string()],
            timeout_ms: 5000,
            concurrent_scans: 100,
        };

        let report = ReportBuilder::new("test-yaml-1".to_string())
            .with_parameters(params)
            .complete()
            .build()
            .unwrap();

        let yaml = generator.generate(&report);
        assert!(yaml.is_ok());
        
        let yaml_str = yaml.unwrap();
        assert!(yaml_str.contains("test-yaml-1"));
        assert!(yaml_str.contains("metadata"));
        assert!(yaml_str.contains("summary"));
    }
}

