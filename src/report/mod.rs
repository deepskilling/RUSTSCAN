/// Report engine for NrMAP
/// 
/// This module provides comprehensive reporting capabilities for scan results
/// including JSON, YAML, HTML, and CLI table formats.

pub mod json;
pub mod yaml;
pub mod html;
pub mod table;

pub use json::JsonReportGenerator;
pub use yaml::YamlReportGenerator;
pub use html::HtmlReportGenerator;
pub use table::TableReportGenerator;

use crate::error::ScanResult;
use crate::scanner::CompleteScanResult;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::info;

/// Report format enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportFormat {
    Json,
    JsonPretty,
    Yaml,
    Html,
    Table,
}

impl std::fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportFormat::Json => write!(f, "json"),
            ReportFormat::JsonPretty => write!(f, "json-pretty"),
            ReportFormat::Yaml => write!(f, "yaml"),
            ReportFormat::Html => write!(f, "html"),
            ReportFormat::Table => write!(f, "table"),
        }
    }
}

impl std::str::FromStr for ReportFormat {
    type Err = crate::error::ScanError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(ReportFormat::Json),
            "json-pretty" | "pretty" => Ok(ReportFormat::JsonPretty),
            "yaml" | "yml" => Ok(ReportFormat::Yaml),
            "html" | "htm" => Ok(ReportFormat::Html),
            "table" | "tbl" => Ok(ReportFormat::Table),
            _ => Err(crate::error::ScanError::validation_error(
                "format",
                format!("Unknown report format: {}", s),
            )),
        }
    }
}

/// Comprehensive scan report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub metadata: ReportMetadata,
    pub summary: ReportSummary,
    pub results: Vec<CompleteScanResult>,
    pub statistics: ReportStatistics,
}

/// Report metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub scan_id: String,
    pub scanner_version: String,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: chrono::DateTime<chrono::Utc>,
    pub duration_seconds: f64,
    pub scan_parameters: ScanParameters,
}

/// Scan parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanParameters {
    pub targets: Vec<IpAddr>,
    pub ports: Vec<u16>,
    pub scan_types: Vec<String>,
    pub timeout_ms: u64,
    pub concurrent_scans: usize,
}

/// Report summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_targets: usize,
    pub targets_up: usize,
    pub targets_down: usize,
    pub total_ports_scanned: usize,
    pub total_open_ports: usize,
    pub total_closed_ports: usize,
    pub total_filtered_ports: usize,
}

/// Report statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportStatistics {
    pub average_scan_time_ms: f64,
    pub fastest_scan_ms: u64,
    pub slowest_scan_ms: u64,
    pub success_rate: f64,
    pub packets_sent: usize,
    pub packets_received: usize,
}

/// Report engine for generating reports in multiple formats
pub struct ReportEngine {
    json_generator: JsonReportGenerator,
    yaml_generator: YamlReportGenerator,
    html_generator: HtmlReportGenerator,
    table_generator: TableReportGenerator,
}

impl ReportEngine {
    /// Create a new report engine
    pub fn new() -> Self {
        info!("Initializing report engine");
        
        Self {
            json_generator: JsonReportGenerator::new(),
            yaml_generator: YamlReportGenerator::new(),
            html_generator: HtmlReportGenerator::new(),
            table_generator: TableReportGenerator::new(),
        }
    }

    /// Generate a report in the specified format
    /// 
    /// # Arguments
    /// * `report` - The scan report to format
    /// * `format` - The desired output format
    pub fn generate(&self, report: &ScanReport, format: ReportFormat) -> ScanResult<String> {
        info!("Generating report in {} format", format);
        
        match format {
            ReportFormat::Json => self.json_generator.generate(report, false),
            ReportFormat::JsonPretty => self.json_generator.generate(report, true),
            ReportFormat::Yaml => self.yaml_generator.generate(report),
            ReportFormat::Html => self.html_generator.generate(report),
            ReportFormat::Table => self.table_generator.generate(report),
        }
    }

    /// Generate and save a report to a file
    /// 
    /// # Arguments
    /// * `report` - The scan report to format
    /// * `format` - The desired output format
    /// * `output_path` - Path to save the report
    pub fn generate_to_file(
        &self,
        report: &ScanReport,
        format: ReportFormat,
        output_path: &str,
    ) -> ScanResult<()> {
        let content = self.generate(report, format)?;
        std::fs::write(output_path, content).map_err(|e| {
            crate::error::ScanError::OutputError {
                message: format!("Failed to write report to {}: {}", output_path, e),
            }
        })?;
        
        info!("Report saved to: {}", output_path);
        Ok(())
    }
}

impl Default for ReportEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a scan report from results
pub struct ReportBuilder {
    scan_id: String,
    start_time: chrono::DateTime<chrono::Utc>,
    end_time: Option<chrono::DateTime<chrono::Utc>>,
    results: Vec<CompleteScanResult>,
    scan_parameters: Option<ScanParameters>,
}

impl ReportBuilder {
    /// Create a new report builder
    pub fn new(scan_id: String) -> Self {
        Self {
            scan_id,
            start_time: chrono::Utc::now(),
            end_time: None,
            results: Vec::new(),
            scan_parameters: None,
        }
    }

    /// Set scan parameters
    pub fn with_parameters(mut self, params: ScanParameters) -> Self {
        self.scan_parameters = Some(params);
        self
    }

    /// Add scan results
    pub fn add_results(mut self, results: Vec<CompleteScanResult>) -> Self {
        self.results = results;
        self
    }

    /// Mark scan as complete
    pub fn complete(mut self) -> Self {
        self.end_time = Some(chrono::Utc::now());
        self
    }

    /// Build the final report
    pub fn build(self) -> ScanResult<ScanReport> {
        let end_time = self.end_time.unwrap_or_else(chrono::Utc::now);
        let duration_seconds = (end_time - self.start_time).num_milliseconds() as f64 / 1000.0;

        // Calculate summary
        let summary = self.calculate_summary();
        
        // Calculate statistics
        let statistics = self.calculate_statistics();

        // Build metadata
        let metadata = ReportMetadata {
            scan_id: self.scan_id,
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            start_time: self.start_time,
            end_time,
            duration_seconds,
            scan_parameters: self.scan_parameters.unwrap_or_else(|| ScanParameters {
                targets: Vec::new(),
                ports: Vec::new(),
                scan_types: Vec::new(),
                timeout_ms: 0,
                concurrent_scans: 0,
            }),
        };

        Ok(ScanReport {
            metadata,
            summary,
            results: self.results.clone(),
            statistics,
        })
    }

    fn calculate_summary(&self) -> ReportSummary {
        use crate::scanner::host_discovery::HostStatus;
        use crate::scanner::tcp_connect::PortStatus;

        let total_targets = self.results.len();
        let targets_up = self.results.iter()
            .filter(|r| r.host_status == HostStatus::Up)
            .count();
        let targets_down = total_targets - targets_up;

        let mut total_open_ports = 0;
        let mut total_closed_ports = 0;
        let mut total_filtered_ports = 0;
        let mut total_ports_scanned = 0;

        for result in &self.results {
            total_ports_scanned += result.tcp_results.len() 
                + result.syn_results.len() 
                + result.udp_results.len();

            for tcp_result in &result.tcp_results {
                match tcp_result.status {
                    PortStatus::Open => total_open_ports += 1,
                    PortStatus::Closed => total_closed_ports += 1,
                    PortStatus::Filtered => total_filtered_ports += 1,
                    _ => {}
                }
            }
        }

        ReportSummary {
            total_targets,
            targets_up,
            targets_down,
            total_ports_scanned,
            total_open_ports,
            total_closed_ports,
            total_filtered_ports,
        }
    }

    fn calculate_statistics(&self) -> ReportStatistics {
        let scan_times: Vec<u64> = self.results.iter()
            .map(|r| r.scan_duration_ms)
            .collect();

        let average_scan_time_ms = if !scan_times.is_empty() {
            scan_times.iter().sum::<u64>() as f64 / scan_times.len() as f64
        } else {
            0.0
        };

        let fastest_scan_ms = scan_times.iter().min().copied().unwrap_or(0);
        let slowest_scan_ms = scan_times.iter().max().copied().unwrap_or(0);

        let success_rate = if !self.results.is_empty() {
            use crate::scanner::host_discovery::HostStatus;
            let successful = self.results.iter()
                .filter(|r| r.host_status == HostStatus::Up)
                .count();
            (successful as f64 / self.results.len() as f64) * 100.0
        } else {
            0.0
        };

        // Aggregate throttle stats if available
        let (packets_sent, packets_received) = self.results.iter()
            .filter_map(|r| r.throttle_stats.as_ref())
            .fold((0, 0), |(sent, received), stats| {
                (sent + stats.total_requests, received + stats.total_successes)
            });

        ReportStatistics {
            average_scan_time_ms,
            fastest_scan_ms,
            slowest_scan_ms,
            success_rate,
            packets_sent,
            packets_received,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_report_format_from_str() {
        assert_eq!("json".parse::<ReportFormat>().unwrap(), ReportFormat::Json);
        assert_eq!("yaml".parse::<ReportFormat>().unwrap(), ReportFormat::Yaml);
        assert_eq!("html".parse::<ReportFormat>().unwrap(), ReportFormat::Html);
        assert_eq!("table".parse::<ReportFormat>().unwrap(), ReportFormat::Table);
    }

    #[test]
    fn test_report_format_display() {
        assert_eq!(format!("{}", ReportFormat::Json), "json");
        assert_eq!(format!("{}", ReportFormat::Yaml), "yaml");
        assert_eq!(format!("{}", ReportFormat::Html), "html");
    }

    #[test]
    fn test_report_builder() {
        let builder = ReportBuilder::new("test-scan-1".to_string())
            .complete();
        
        let report = builder.build().unwrap();
        assert_eq!(report.metadata.scan_id, "test-scan-1");
        assert_eq!(report.results.len(), 0);
    }

    #[test]
    fn test_report_engine_creation() {
        let _engine = ReportEngine::new();
        // ReportEngine is a zero-sized type (stateless), so just test that it can be created
        assert!(true);
    }
}

