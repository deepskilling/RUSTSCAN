/// HTML report generator
/// 
/// This module generates HTML format reports for scan results with styling.

use crate::error::ScanResult;
use crate::report::ScanReport;
use crate::scanner::host_discovery::HostStatus;
use crate::scanner::tcp_connect::PortStatus;
use tracing::debug;

/// HTML report generator
pub struct HtmlReportGenerator;

impl HtmlReportGenerator {
    /// Create a new HTML report generator
    pub fn new() -> Self {
        Self
    }

    /// Generate an HTML report
    /// 
    /// # Arguments
    /// * `report` - The scan report to format
    pub fn generate(&self, report: &ScanReport) -> ScanResult<String> {
        debug!("Generating HTML report");
        
        let mut html = String::new();
        
        // HTML header
        html.push_str(&self.generate_header());
        
        // Report metadata
        html.push_str(&self.generate_metadata(&report));
        
        // Summary section
        html.push_str(&self.generate_summary(&report));
        
        // Statistics section
        html.push_str(&self.generate_statistics(&report));
        
        // Results table
        html.push_str(&self.generate_results_table(&report));
        
        // HTML footer
        html.push_str(&self.generate_footer());
        
        Ok(html)
    }

    fn generate_header(&self) -> String {
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NrMAP Scan Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
            margin-bottom: 15px;
            border-left: 4px solid #3498db;
            padding-left: 10px;
        }
        .metadata, .summary, .statistics {
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .metadata-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        .metadata-item {
            background: white;
            padding: 10px;
            border-radius: 4px;
        }
        .metadata-label {
            font-weight: bold;
            color: #7f8c8d;
            font-size: 0.9em;
        }
        .metadata-value {
            color: #2c3e50;
            font-size: 1.1em;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        .stat-card {
            background: white;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            border-top: 3px solid #3498db;
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #3498db;
        }
        .stat-label {
            color: #7f8c8d;
            font-size: 0.9em;
            margin-top: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: white;
        }
        th {
            background: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        td {
            padding: 10px 12px;
            border-bottom: 1px solid #ecf0f1;
        }
        tr:hover {
            background: #f8f9fa;
        }
        .status-up { color: #27ae60; font-weight: bold; }
        .status-down { color: #e74c3c; font-weight: bold; }
        .port-open { color: #27ae60; font-weight: bold; }
        .port-closed { color: #95a5a6; }
        .port-filtered { color: #f39c12; }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
            color: #7f8c8d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 NrMAP Scan Report</h1>
"#.to_string()
    }

    fn generate_metadata(&self, report: &ScanReport) -> String {
        format!(r#"
        <h2>Scan Metadata</h2>
        <div class="metadata">
            <div class="metadata-grid">
                <div class="metadata-item">
                    <div class="metadata-label">Scan ID</div>
                    <div class="metadata-value">{}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Scanner Version</div>
                    <div class="metadata-value">{}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Start Time</div>
                    <div class="metadata-value">{}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">End Time</div>
                    <div class="metadata-value">{}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Duration</div>
                    <div class="metadata-value">{:.2} seconds</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Targets</div>
                    <div class="metadata-value">{}</div>
                </div>
            </div>
        </div>
"#,
            report.metadata.scan_id,
            report.metadata.scanner_version,
            report.metadata.start_time.format("%Y-%m-%d %H:%M:%S UTC"),
            report.metadata.end_time.format("%Y-%m-%d %H:%M:%S UTC"),
            report.metadata.duration_seconds,
            report.metadata.scan_parameters.targets.len()
        )
    }

    fn generate_summary(&self, report: &ScanReport) -> String {
        format!(r#"
        <h2>Summary</h2>
        <div class="summary">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{}</div>
                    <div class="stat-label">Total Targets</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #27ae60;">{}</div>
                    <div class="stat-label">Targets Up</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #e74c3c;">{}</div>
                    <div class="stat-label">Targets Down</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{}</div>
                    <div class="stat-label">Ports Scanned</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #27ae60;">{}</div>
                    <div class="stat-label">Open Ports</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #95a5a6;">{}</div>
                    <div class="stat-label">Closed Ports</div>
                </div>
            </div>
        </div>
"#,
            report.summary.total_targets,
            report.summary.targets_up,
            report.summary.targets_down,
            report.summary.total_ports_scanned,
            report.summary.total_open_ports,
            report.summary.total_closed_ports
        )
    }

    fn generate_statistics(&self, report: &ScanReport) -> String {
        format!(r#"
        <h2>Statistics</h2>
        <div class="statistics">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{:.2}ms</div>
                    <div class="stat-label">Average Scan Time</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{}ms</div>
                    <div class="stat-label">Fastest Scan</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{}ms</div>
                    <div class="stat-label">Slowest Scan</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{:.1}%</div>
                    <div class="stat-label">Success Rate</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{}</div>
                    <div class="stat-label">Packets Sent</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{}</div>
                    <div class="stat-label">Packets Received</div>
                </div>
            </div>
        </div>
"#,
            report.statistics.average_scan_time_ms,
            report.statistics.fastest_scan_ms,
            report.statistics.slowest_scan_ms,
            report.statistics.success_rate,
            report.statistics.packets_sent,
            report.statistics.packets_received
        )
    }

    fn generate_results_table(&self, report: &ScanReport) -> String {
        let mut table = String::from(r#"
        <h2>Detailed Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Target</th>
                    <th>Host Status</th>
                    <th>Open Ports</th>
                    <th>Scan Time (ms)</th>
                </tr>
            </thead>
            <tbody>
"#);

        for result in &report.results {
            let host_status_class = match result.host_status {
                HostStatus::Up => "status-up",
                HostStatus::Down => "status-down",
                _ => "",
            };

            let open_ports: Vec<String> = result.tcp_results.iter()
                .filter(|r| r.status == PortStatus::Open)
                .map(|r| r.port.to_string())
                .collect();

            let open_ports_str = if open_ports.is_empty() {
                "None".to_string()
            } else {
                open_ports.join(", ")
            };

            table.push_str(&format!(r#"
                <tr>
                    <td>{}</td>
                    <td class="{}">{:?}</td>
                    <td class="port-open">{}</td>
                    <td>{}</td>
                </tr>
"#,
                result.target,
                host_status_class,
                result.host_status,
                open_ports_str,
                result.scan_duration_ms
            ));
        }

        table.push_str(r#"
            </tbody>
        </table>
"#);

        table
    }

    fn generate_footer(&self) -> String {
        format!(r#"
        <div class="footer">
            <p>Generated by NrMAP Scanner v{}</p>
            <p>Report generated at {}</p>
        </div>
    </div>
</body>
</html>
"#,
            env!("CARGO_PKG_VERSION"),
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        )
    }
}

impl Default for HtmlReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::ReportBuilder;

    #[test]
    fn test_html_generator_creation() {
        let generator = HtmlReportGenerator::new();
        assert!(std::mem::size_of_val(&generator) >= 0);
    }

    #[test]
    fn test_generate_html() {
        let generator = HtmlReportGenerator::new();
        
        let report = ReportBuilder::new("test-html-1".to_string())
            .complete()
            .build()
            .unwrap();

        let html = generator.generate(&report);
        assert!(html.is_ok());
        
        let html_str = html.unwrap();
        assert!(html_str.contains("<!DOCTYPE html>"));
        assert!(html_str.contains("NrMAP Scan Report"));
        assert!(html_str.contains("test-html-1"));
        assert!(html_str.contains("</html>"));
    }

    #[test]
    fn test_html_has_css_styling() {
        let generator = HtmlReportGenerator::new();
        
        let report = ReportBuilder::new("test-css".to_string())
            .complete()
            .build()
            .unwrap();

        let html = generator.generate(&report).unwrap();
        assert!(html.contains("<style>"));
        assert!(html.contains("font-family"));
        assert!(html.contains("color"));
    }
}

