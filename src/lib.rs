/// NrMAP - Network Scanner Library
/// 
/// A high-performance network scanner written in Rust with comprehensive
/// logging, error handling, and configuration management.

// Module declarations
pub mod config;
pub mod error;
pub mod logging;
pub mod scanner;
pub mod packet;
pub mod detection;
pub mod distributed;
pub mod cli;
pub mod report;
pub mod os_fingerprint;

// Re-export commonly used types
pub use config::AppConfig;
pub use error::{ScanError, ScanResult};
pub use scanner::{Scanner, ScanType};
pub use packet::{PacketEngine, PacketBuilder};
pub use detection::{DetectionEngine, ServiceBanner, ServiceFingerprint, OsMatch};
pub use distributed::{DistributedScanner, ScanAgent, ScanScheduler};
pub use cli::{Cli, ScanProfile, OutputFormatter, OutputFormat};
pub use report::{ReportEngine, ReportBuilder, ScanReport, ReportFormat};
pub use os_fingerprint::{OsFingerprintEngine, OsFingerprint, OsMatchResult};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Initialize the library with configuration
/// 
/// This is the main entry point for library users. It loads configuration,
/// initializes logging, and returns a configured scanner instance.
/// 
/// # Arguments
/// * `config_path` - Optional path to configuration file (uses default if None)
/// 
/// # Returns
/// * `ScanResult<(Scanner, Option<tracing_appender::non_blocking::WorkerGuard>)>`
///   - Scanner instance and logging guard (must be kept alive)
/// 
/// # Example
/// ```no_run
/// use nrmap::{init_library, ScanType};
/// use std::net::IpAddr;
/// 
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let (scanner, _guard) = init_library(Some("config.toml")).await?;
///     
///     let target: IpAddr = "127.0.0.1".parse()?;
///     let ports = vec![80, 443, 22];
///     let scan_types = vec![ScanType::TcpConnect];
///     
///     let results = scanner.scan(target, ports, scan_types).await?;
///     println!("{}", results);
///     
///     Ok(())
/// }
/// ```
pub async fn init_library<P: AsRef<std::path::Path>>(
    config_path: Option<P>,
) -> ScanResult<(Scanner, Option<tracing_appender::non_blocking::WorkerGuard>)> {
    use tracing::info;

    // Load configuration
    let config = if let Some(path) = config_path {
        AppConfig::from_file(path)?
    } else {
        AppConfig::default()
    };

    // Initialize logging
    let guard = logging::init_logging(&config.logging)?;

    info!("{} v{} initialized", NAME, VERSION);

    // Create scanner
    let scanner = Scanner::new(config.scanner);

    Ok((scanner, guard))
}

/// Parse a port range string (e.g., "1-1000", "80,443,8080")
/// 
/// # Arguments
/// * `port_str` - Port range string
/// 
/// # Returns
/// * `ScanResult<Vec<u16>>` - Vector of port numbers
/// 
/// # Examples
/// ```
/// use nrmap::parse_port_range;
/// 
/// let ports = parse_port_range("80,443,8080").unwrap();
/// assert_eq!(ports, vec![80, 443, 8080]);
/// 
/// let range = parse_port_range("20-25").unwrap();
/// assert_eq!(range, vec![20, 21, 22, 23, 24, 25]);
/// ```
pub fn parse_port_range(port_str: &str) -> ScanResult<Vec<u16>> {
    let mut ports = Vec::new();

    for part in port_str.split(',') {
        let part = part.trim();
        
        if part.contains('-') {
            // Range like "1-100"
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() != 2 {
                return Err(ScanError::validation_error(
                    "port_range",
                    format!("Invalid port range format: {}", part),
                ));
            }

            let start: u16 = range_parts[0].parse().map_err(|_| {
                ScanError::validation_error("port_range", format!("Invalid port number: {}", range_parts[0]))
            })?;

            let end: u16 = range_parts[1].parse().map_err(|_| {
                ScanError::validation_error("port_range", format!("Invalid port number: {}", range_parts[1]))
            })?;

            if start > end {
                return Err(ScanError::InvalidPortRange { start, end });
            }

            ports.extend(start..=end);
        } else {
            // Single port
            let port: u16 = part.parse().map_err(|_| {
                ScanError::validation_error("port", format!("Invalid port number: {}", part))
            })?;
            ports.push(port);
        }
    }

    if ports.is_empty() {
        return Err(ScanError::validation_error(
            "port_range",
            "No ports specified",
        ));
    }

    // Remove duplicates and sort
    ports.sort_unstable();
    ports.dedup();

    Ok(ports)
}

/// Parse common port presets
/// 
/// # Arguments
/// * `preset` - Preset name (e.g., "common", "all", "web")
/// 
/// # Returns
/// * `ScanResult<Vec<u16>>` - Vector of port numbers
pub fn parse_port_preset(preset: &str) -> ScanResult<Vec<u16>> {
    match preset.to_lowercase().as_str() {
        "common" | "top100" => Ok(vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
        ]),
        "web" => Ok(vec![80, 443, 8000, 8080, 8443, 8888]),
        "mail" => Ok(vec![25, 110, 143, 465, 587, 993, 995]),
        "database" => Ok(vec![1433, 3306, 5432, 27017, 6379]),
        "all" => Ok((1..=65535).collect()),
        _ => Err(ScanError::validation_error(
            "preset",
            format!("Unknown port preset: {}", preset),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_range_single() {
        let ports = parse_port_range("80").unwrap();
        assert_eq!(ports, vec![80]);
    }

    #[test]
    fn test_parse_port_range_multiple() {
        let ports = parse_port_range("80,443,8080").unwrap();
        assert_eq!(ports, vec![80, 443, 8080]);
    }

    #[test]
    fn test_parse_port_range_range() {
        let ports = parse_port_range("20-25").unwrap();
        assert_eq!(ports, vec![20, 21, 22, 23, 24, 25]);
    }

    #[test]
    fn test_parse_port_range_mixed() {
        let ports = parse_port_range("80,443,8000-8003").unwrap();
        assert_eq!(ports, vec![80, 443, 8000, 8001, 8002, 8003]);
    }

    #[test]
    fn test_parse_port_range_duplicates() {
        let ports = parse_port_range("80,80,443").unwrap();
        assert_eq!(ports, vec![80, 443]);
    }

    #[test]
    fn test_parse_port_range_invalid() {
        assert!(parse_port_range("invalid").is_err());
        assert!(parse_port_range("100-50").is_err());
        assert!(parse_port_range("").is_err());
    }

    #[test]
    fn test_parse_port_preset() {
        let common = parse_port_preset("common").unwrap();
        assert!(!common.is_empty());
        
        let web = parse_port_preset("web").unwrap();
        assert!(web.contains(&80));
        assert!(web.contains(&443));
    }

    #[test]
    fn test_version_constants() {
        assert!(!VERSION.is_empty());
        assert!(!NAME.is_empty());
    }
}

