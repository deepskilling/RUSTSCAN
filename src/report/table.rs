/// CLI table report generator
/// 
/// This module generates formatted ASCII table reports for scan results.

use crate::error::ScanResult;
use crate::report::ScanReport;
use crate::scanner::host_discovery::HostStatus;
use crate::scanner::tcp_connect::PortStatus;
use tracing::debug;

/// Table report generator
pub struct TableReportGenerator;

impl TableReportGenerator {
    /// Create a new table report generator
    pub fn new() -> Self {
        Self
    }

    /// Generate a table report
    /// 
    /// # Arguments
    /// * `report` - The scan report to format
    pub fn generate(&self, report: &ScanReport) -> ScanResult<String> {
        debug!("Generating table report");
        
        let mut output = String::new();
        
        // Title
        output.push_str(&self.generate_title());
        
        // Metadata section
        output.push_str(&self.generate_metadata_table(&report));
        
        // Summary section
        output.push_str(&self.generate_summary_table(&report));
        
        // Statistics section
        output.push_str(&self.generate_statistics_table(&report));
        
        // Results table
        output.push_str(&self.generate_results_table(&report));
        
        Ok(output)
    }

    fn generate_title(&self) -> String {
        format!("\n{}\n{}\n{}\n\n",
            "╔═══════════════════════════════════════════════════════════════════════╗",
            "║                      NrMAP SCAN REPORT                                ║",
            "╚═══════════════════════════════════════════════════════════════════════╝"
        )
    }

    fn generate_metadata_table(&self, report: &ScanReport) -> String {
        format!(
r#"METADATA
{}
│ Scan ID:            {}
│ Scanner Version:    {}
│ Start Time:         {}
│ End Time:           {}
│ Duration:           {:.2} seconds
│ Targets:            {}
│ Ports:              {}
│ Scan Types:         {}
{}

"#,
            "┌───────────────────────────────────────────────────────────────────────┐",
            report.metadata.scan_id,
            report.metadata.scanner_version,
            report.metadata.start_time.format("%Y-%m-%d %H:%M:%S UTC"),
            report.metadata.end_time.format("%Y-%m-%d %H:%M:%S UTC"),
            report.metadata.duration_seconds,
            report.metadata.scan_parameters.targets.len(),
            report.metadata.scan_parameters.ports.len(),
            report.metadata.scan_parameters.scan_types.join(", "),
            "└───────────────────────────────────────────────────────────────────────┘"
        )
    }

    fn generate_summary_table(&self, report: &ScanReport) -> String {
        format!(
r#"SUMMARY
{}
│                                                                           │
│  Total Targets:          {:>10}                                       │
│  Targets Up:             {:>10}  (✓)                                   │
│  Targets Down:           {:>10}  (✗)                                   │
│  Total Ports Scanned:    {:>10}                                       │
│  Open Ports:             {:>10}  (✓)                                   │
│  Closed Ports:           {:>10}                                       │
│  Filtered Ports:         {:>10}                                       │
│                                                                           │
{}

"#,
            "┌───────────────────────────────────────────────────────────────────────┐",
            report.summary.total_targets,
            report.summary.targets_up,
            report.summary.targets_down,
            report.summary.total_ports_scanned,
            report.summary.total_open_ports,
            report.summary.total_closed_ports,
            report.summary.total_filtered_ports,
            "└───────────────────────────────────────────────────────────────────────┘"
        )
    }

    fn generate_statistics_table(&self, report: &ScanReport) -> String {
        format!(
r#"STATISTICS
{}
│                                                                           │
│  Average Scan Time:      {:>10.2} ms                                   │
│  Fastest Scan:           {:>10} ms                                     │
│  Slowest Scan:           {:>10} ms                                     │
│  Success Rate:           {:>10.1} %                                     │
│  Packets Sent:           {:>10}                                       │
│  Packets Received:       {:>10}                                       │
│                                                                           │
{}

"#,
            "┌───────────────────────────────────────────────────────────────────────┐",
            report.statistics.average_scan_time_ms,
            report.statistics.fastest_scan_ms,
            report.statistics.slowest_scan_ms,
            report.statistics.success_rate,
            report.statistics.packets_sent,
            report.statistics.packets_received,
            "└───────────────────────────────────────────────────────────────────────┘"
        )
    }

    fn generate_results_table(&self, report: &ScanReport) -> String {
        if report.results.is_empty() {
            return String::from("DETAILED RESULTS\nNo scan results available.\n\n");
        }

        let mut table = String::from(
r#"DETAILED RESULTS
┌───────────────────┬────────────┬─────────────────────────┬──────────────┐
│ Target            │ Status     │ Open Ports              │ Scan Time    │
├───────────────────┼────────────┼─────────────────────────┼──────────────┤
"#);

        for result in &report.results {
            let status_str = match result.host_status {
                HostStatus::Up => "UP ✓",
                HostStatus::Down => "DOWN ✗",
                HostStatus::Unknown => "UNKNOWN",
            };

            let open_ports: Vec<String> = result.tcp_results.iter()
                .filter(|r| r.status == PortStatus::Open)
                .map(|r| r.port.to_string())
                .collect();

            let open_ports_str = if open_ports.is_empty() {
                "None".to_string()
            } else if open_ports.len() > 5 {
                format!("{} ({} total)", &open_ports[..5].join(", "), open_ports.len())
            } else {
                open_ports.join(", ")
            };

            table.push_str(&format!(
                "│ {:<17} │ {:<10} │ {:<23} │ {:>10} ms │\n",
                format!("{}", result.target).chars().take(17).collect::<String>(),
                status_str,
                open_ports_str.chars().take(23).collect::<String>(),
                result.scan_duration_ms
            ));
        }

        table.push_str("└───────────────────┴────────────┴─────────────────────────┴──────────────┘\n\n");
        table
    }

    /// Generate a simple summary table (for quick viewing)
    pub fn generate_summary_only(&self, report: &ScanReport) -> ScanResult<String> {
        let mut output = String::new();
        
        output.push_str(&format!("\n{}\n", "═".repeat(70)));
        output.push_str(&format!("  Scan: {} (Duration: {:.2}s)\n", 
            report.metadata.scan_id,
            report.metadata.duration_seconds
        ));
        output.push_str(&format!("{}\n", "═".repeat(70)));
        
        output.push_str(&format!("  Targets: {} total, {} up, {} down\n",
            report.summary.total_targets,
            report.summary.targets_up,
            report.summary.targets_down
        ));
        
        output.push_str(&format!("  Ports: {} scanned, {} open, {} closed\n",
            report.summary.total_ports_scanned,
            report.summary.total_open_ports,
            report.summary.total_closed_ports
        ));
        
        output.push_str(&format!("  Success Rate: {:.1}%\n", report.statistics.success_rate));
        output.push_str(&format!("{}\n\n", "═".repeat(70)));
        
        Ok(output)
    }
}

impl Default for TableReportGenerator {
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
    fn test_table_generator_creation() {
        let generator = TableReportGenerator::new();
        assert!(std::mem::size_of_val(&generator) >= 0);
    }

    #[test]
    fn test_generate_table() {
        let generator = TableReportGenerator::new();
        
        let params = ScanParameters {
            targets: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
            ports: vec![80, 443],
            scan_types: vec!["TcpConnect".to_string()],
            timeout_ms: 5000,
            concurrent_scans: 100,
        };

        let report = ReportBuilder::new("test-table-1".to_string())
            .with_parameters(params)
            .complete()
            .build()
            .unwrap();

        let table = generator.generate(&report);
        assert!(table.is_ok());
        
        let table_str = table.unwrap();
        assert!(table_str.contains("NrMAP SCAN REPORT"));
        assert!(table_str.contains("test-table-1"));
        assert!(table_str.contains("METADATA"));
        assert!(table_str.contains("SUMMARY"));
        assert!(table_str.contains("STATISTICS"));
    }

    #[test]
    fn test_generate_summary_only() {
        let generator = TableReportGenerator::new();
        
        let report = ReportBuilder::new("test-summary".to_string())
            .complete()
            .build()
            .unwrap();

        let summary = generator.generate_summary_only(&report);
        assert!(summary.is_ok());
        
        let summary_str = summary.unwrap();
        assert!(summary_str.contains("test-summary"));
        assert!(summary_str.contains("Targets:"));
        assert!(summary_str.contains("Ports:"));
    }

    #[test]
    fn test_table_has_box_drawing() {
        let generator = TableReportGenerator::new();
        
        let report = ReportBuilder::new("test-box".to_string())
            .complete()
            .build()
            .unwrap();

        let table = generator.generate(&report).unwrap();
        assert!(table.contains("═"));
        assert!(table.contains("│"));
        assert!(table.contains("┌"));
        assert!(table.contains("└"));
    }
}

