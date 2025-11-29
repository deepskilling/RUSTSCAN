/// NrMAP - Network Scanner CLI
/// 
/// Main entry point for the command-line interface

use clap::{Parser, Subcommand};
use nrmap::{init_library, parse_port_preset, parse_port_range, ScanType};
use std::net::IpAddr;
use std::process;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "nrmap")]
#[command(version = nrmap::VERSION)]
#[command(about = "High-performance network scanner", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a target host
    Scan {
        /// Target IP address
        #[arg(short, long)]
        target: String,

        /// Ports to scan (e.g., "80,443" or "1-1000")
        #[arg(short, long)]
        ports: Option<String>,

        /// Port preset (common, web, mail, database, all)
        #[arg(long)]
        preset: Option<String>,

        /// Scan type: tcp, syn, udp (can specify multiple)
        #[arg(short = 't', long, default_value = "tcp")]
        scan_type: Vec<String>,

        /// Maximum concurrent scans
        #[arg(short, long)]
        concurrency: Option<usize>,
    },

    /// Scan multiple targets from a file
    ScanFile {
        /// File containing target IP addresses (one per line)
        #[arg(short, long)]
        file: String,

        /// Ports to scan
        #[arg(short, long)]
        ports: Option<String>,

        /// Port preset
        #[arg(long)]
        preset: Option<String>,

        /// Scan type
        #[arg(short = 't', long, default_value = "tcp")]
        scan_type: Vec<String>,
    },

    /// Show version information
    Version,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize library
    let (scanner, _guard) = match init_library(Some(&cli.config)).await {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Failed to initialize: {}", e);
            eprintln!("Using default configuration...");
            
            match init_library::<&str>(None).await {
                Ok(result) => result,
                Err(e) => {
                    eprintln!("Fatal error: {}", e);
                    process::exit(1);
                }
            }
        }
    };

    // Execute command
    let result = match cli.command {
        Commands::Scan {
            target,
            ports,
            preset,
            scan_type,
            concurrency,
        } => {
            handle_scan(scanner, target, ports, preset, scan_type, concurrency).await
        }
        Commands::ScanFile {
            file,
            ports,
            preset,
            scan_type,
        } => {
            handle_scan_file(scanner, file, ports, preset, scan_type).await
        }
        Commands::Version => {
            handle_version();
            Ok(())
        }
    };

    if let Err(e) = result {
        error!("Error: {}", e);
        process::exit(1);
    }
}

async fn handle_scan(
    scanner: nrmap::Scanner,
    target: String,
    ports_str: Option<String>,
    preset: Option<String>,
    scan_types: Vec<String>,
    _concurrency: Option<usize>,
) -> nrmap::ScanResult<()> {
    // Parse target IP
    let target_ip: IpAddr = target
        .parse()
        .map_err(|_| nrmap::ScanError::invalid_target(target, "Invalid IP address"))?;

    // Parse ports
    let ports = if let Some(preset) = preset {
        parse_port_preset(&preset)?
    } else if let Some(ports_str) = ports_str {
        parse_port_range(&ports_str)?
    } else {
        // Default to common ports
        parse_port_preset("common")?
    };

    // Parse scan types
    let scan_types: Vec<ScanType> = scan_types
        .iter()
        .map(|s| match s.to_lowercase().as_str() {
            "tcp" | "connect" => Ok(ScanType::TcpConnect),
            "syn" => Ok(ScanType::TcpSyn),
            "udp" => Ok(ScanType::Udp),
            _ => Err(nrmap::ScanError::validation_error(
                "scan_type",
                format!("Unknown scan type: {}", s),
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;

    info!(
        "Starting scan: target={}, ports={}, scan_types={:?}",
        target_ip,
        ports.len(),
        scan_types
    );

    // Perform scan
    let results = scanner.scan(target_ip, ports, scan_types).await?;

    // Display results
    println!("\n{}", "=".repeat(80));
    println!("{}", results);
    println!("{}", "=".repeat(80));

    Ok(())
}

async fn handle_scan_file(
    scanner: nrmap::Scanner,
    file_path: String,
    ports_str: Option<String>,
    preset: Option<String>,
    scan_types: Vec<String>,
) -> nrmap::ScanResult<()> {
    use std::fs;

    // Read targets from file
    let content = fs::read_to_string(&file_path).map_err(|e| {
        nrmap::ScanError::scanner_error(format!("Failed to read file {}: {}", file_path, e))
    })?;

    let targets: Vec<IpAddr> = content
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim().starts_with('#'))
        .map(|line| {
            line.trim().parse().map_err(|_| {
                nrmap::ScanError::invalid_target(line, "Invalid IP address in file")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    if targets.is_empty() {
        return Err(nrmap::ScanError::validation_error(
            "targets",
            "No valid targets found in file",
        ));
    }

    // Parse ports
    let ports = if let Some(preset) = preset {
        parse_port_preset(&preset)?
    } else if let Some(ports_str) = ports_str {
        parse_port_range(&ports_str)?
    } else {
        parse_port_preset("common")?
    };

    // Parse scan types
    let scan_types: Vec<ScanType> = scan_types
        .iter()
        .map(|s| match s.to_lowercase().as_str() {
            "tcp" | "connect" => Ok(ScanType::TcpConnect),
            "syn" => Ok(ScanType::TcpSyn),
            "udp" => Ok(ScanType::Udp),
            _ => Err(nrmap::ScanError::validation_error(
                "scan_type",
                format!("Unknown scan type: {}", s),
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;

    info!(
        "Starting scan: {} targets, {} ports per target",
        targets.len(),
        ports.len()
    );

    // Perform scans
    let results = scanner.scan_multiple(targets, ports, scan_types).await?;

    // Display results
    println!("\n{}", "=".repeat(80));
    for result in results {
        println!("{}", result);
        println!("{}", "-".repeat(80));
    }
    println!("{}", "=".repeat(80));

    Ok(())
}

fn handle_version() {
    println!("{} version {}", nrmap::NAME, nrmap::VERSION);
    println!("High-performance network scanner written in Rust");
    println!("\nFeatures:");
    println!("  - TCP Connect scan");
    println!("  - TCP SYN scan (requires root)");
    println!("  - UDP scan");
    println!("  - Host discovery");
    println!("  - Adaptive throttling");
    println!("  - Comprehensive logging");
    println!("  - Configuration file support");
}

