/// Report engine example
/// 
/// This example demonstrates comprehensive report generation in multiple formats:
/// JSON, YAML, HTML, and CLI tables.

use nrmap::report::{ReportEngine, ReportBuilder, ReportFormat, ScanParameters};
use std::net::{IpAddr, Ipv4Addr};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("NrMAP Report Engine Example\n");

    // Example 1: Build a comprehensive report
    println!("Example 1: Building a Scan Report");
    println!("{}", "-".repeat(70));
    
    let scan_id = format!("scan-{}", uuid::Uuid::new_v4());
    
    let scan_params = ScanParameters {
        targets: vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)),
        ],
        ports: vec![21, 22, 23, 25, 80, 443, 3306, 3389, 8080, 8443],
        scan_types: vec!["TcpConnect".to_string(), "TcpSyn".to_string()],
        timeout_ms: 5000,
        concurrent_scans: 100,
    };
    
    let report = ReportBuilder::new(scan_id.clone())
        .with_parameters(scan_params)
        .complete()
        .build()?;
    
    println!("Report built successfully:");
    println!("  Scan ID: {}", report.metadata.scan_id);
    println!("  Duration: {:.2} seconds", report.metadata.duration_seconds);
    println!("  Targets: {}", report.summary.total_targets);
    println!();

    // Example 2: Generate JSON report
    println!("Example 2: JSON Report (Pretty)");
    println!("{}", "-".repeat(70));
    
    let engine = ReportEngine::new();
    let json_report = engine.generate(&report, ReportFormat::JsonPretty)?;
    
    // Show first 500 characters
    let preview = if json_report.len() > 500 {
        format!("{}...", &json_report[..500])
    } else {
        json_report.clone()
    };
    println!("{}\n", preview);

    // Example 3: Generate YAML report
    println!("Example 3: YAML Report");
    println!("{}", "-".repeat(70));
    
    let yaml_report = engine.generate(&report, ReportFormat::Yaml)?;
    
    // Show first 500 characters
    let preview = if yaml_report.len() > 500 {
        format!("{}...", &yaml_report[..500])
    } else {
        yaml_report.clone()
    };
    println!("{}\n", preview);

    // Example 4: Generate CLI Table report
    println!("Example 4: CLI Table Report");
    println!("{}", "-".repeat(70));
    
    let table_report = engine.generate(&report, ReportFormat::Table)?;
    println!("{}", table_report);

    // Example 5: Generate HTML report
    println!("Example 5: HTML Report");
    println!("{}", "-".repeat(70));
    
    let html_report = engine.generate(&report, ReportFormat::Html)?;
    println!("HTML report generated ({} bytes)", html_report.len());
    println!("Contains: <!DOCTYPE html>, <style>, tables, etc.\n");

    // Example 6: Save reports to files
    println!("Example 6: Save Reports to Files");
    println!("{}", "-".repeat(70));
    
    let output_dir = "./reports";
    std::fs::create_dir_all(output_dir).ok();
    
    let formats = vec![
        (ReportFormat::JsonPretty, "json"),
        (ReportFormat::Yaml, "yaml"),
        (ReportFormat::Html, "html"),
        (ReportFormat::Table, "txt"),
    ];
    
    for (format, ext) in formats {
        let filename = format!("{}/report_{}.{}", output_dir, scan_id, ext);
        engine.generate_to_file(&report, format, &filename)?;
        println!("  ✓ Saved {} report: {}", format, filename);
    }
    println!();

    // Example 7: Report summary
    println!("Example 7: Report Summary");
    println!("{}", "-".repeat(70));
    
    println!("Metadata:");
    println!("  Scanner Version: {}", report.metadata.scanner_version);
    println!("  Start Time: {}", report.metadata.start_time.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("  End Time: {}", report.metadata.end_time.format("%Y-%m-%d %H:%M:%S UTC"));
    println!();
    
    println!("Summary:");
    println!("  Total Targets: {}", report.summary.total_targets);
    println!("  Targets Up: {}", report.summary.targets_up);
    println!("  Total Ports Scanned: {}", report.summary.total_ports_scanned);
    println!("  Open Ports: {}", report.summary.total_open_ports);
    println!();
    
    println!("Statistics:");
    println!("  Average Scan Time: {:.2} ms", report.statistics.average_scan_time_ms);
    println!("  Success Rate: {:.1}%", report.statistics.success_rate);
    println!("  Packets Sent: {}", report.statistics.packets_sent);
    println!();

    println!("Example completed!");
    println!("\nTip: Check the ./reports directory for generated report files");
    println!("  - report_*.json   - JSON format");
    println!("  - report_*.yaml   - YAML format");
    println!("  - report_*.html   - HTML format (open in browser)");
    println!("  - report_*.txt    - CLI table format");

    Ok(())
}

