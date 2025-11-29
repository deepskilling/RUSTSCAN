/// Simple scan example
/// 
/// This example demonstrates basic usage of the NrMAP library

use nrmap::{init_library, parse_port_range, ScanType};
use std::net::IpAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("NrMAP Simple Scan Example\n");

    // Initialize library with default config
    let (scanner, _guard) = init_library::<&str>(None).await?;
    println!("Scanner initialized");

    // Define scan target
    let target: IpAddr = "127.0.0.1".parse()?;
    println!("Target: {}", target);

    // Parse port range
    let ports = parse_port_range("80,443,22,21,25")?;
    println!("Ports: {:?}", ports);

    // Define scan type
    let scan_types = vec![ScanType::TcpConnect];
    println!("Scan type: TCP Connect\n");

    // Perform scan
    println!("Starting scan...");
    let results = scanner.scan(target, ports, scan_types).await?;

    // Display results
    println!("\n{}", "=".repeat(80));
    println!("{}", results);
    println!("{}", "=".repeat(80));

    // Display open ports
    let open_ports: Vec<_> = results
        .tcp_results
        .iter()
        .filter(|r| r.status == nrmap::scanner::tcp_connect::PortStatus::Open)
        .collect();

    println!("\nSummary:");
    println!("  Total ports scanned: {}", results.tcp_results.len());
    println!("  Open ports: {}", open_ports.len());
    println!("  Scan duration: {}ms", results.scan_duration_ms);

    Ok(())
}

