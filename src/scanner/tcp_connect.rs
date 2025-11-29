/// TCP Connect scan module for NrMAP
/// 
/// This module implements the TCP connect() scan method, which completes
/// the full TCP three-way handshake. This is the most reliable but also
/// the most detectable scanning method.

use crate::config::TcpConnectConfig;
use crate::error::{ScanError, ScanResult};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Port scan result
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
    Unknown,
}

/// TCP connect scan result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TcpConnectResult {
    pub target: IpAddr,
    pub port: u16,
    pub status: PortStatus,
    pub response_time_ms: Option<u64>,
    pub banner: Option<String>,
}

/// TCP connect scanner
pub struct TcpConnectScanner {
    config: TcpConnectConfig,
}

impl TcpConnectScanner {
    /// Create a new TCP connect scanner
    pub fn new(config: TcpConnectConfig) -> Self {
        info!(
            "Initializing TCP connect scanner: timeout={}ms, retries={}",
            config.timeout_ms, config.retries
        );
        Self { config }
    }

    /// Scan a single port on a target host
    /// 
    /// # Arguments
    /// * `target` - IP address to scan
    /// * `port` - Port number to scan
    /// 
    /// # Returns
    /// * `ScanResult<TcpConnectResult>` - Scan result with port status
    pub async fn scan_port(&self, target: IpAddr, port: u16) -> ScanResult<TcpConnectResult> {
        if !self.config.enabled {
            return Err(ScanError::scanner_error("TCP connect scan is disabled"));
        }

        debug!("TCP connect scan: {}:{}", target, port);

        let mut last_error = None;
        let start = std::time::Instant::now();

        // Attempt scan with retries
        for attempt in 0..=self.config.retries {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(self.config.retry_delay_ms)).await;
                debug!("Retrying {}:{} (attempt {})", target, port, attempt + 1);
            }

            match self.try_connect(target, port).await {
                Ok(result) => {
                    let elapsed = start.elapsed();
                    crate::log_scan_event!(
                        tracing::Level::INFO,
                        target,
                        port,
                        result.status.to_string(),
                        format!("TCP connect scan completed in {}ms", elapsed.as_millis())
                    );
                    return Ok(result);
                }
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }

        // All retries failed
        let error = last_error.unwrap_or_else(|| {
            ScanError::tcp_scan_failed(target, port, "All retries exhausted")
        });

        warn!("TCP connect scan failed for {}:{} after {} retries", target, port, self.config.retries);
        Err(error)
    }

    /// Attempt a single TCP connect
    async fn try_connect(&self, target: IpAddr, port: u16) -> ScanResult<TcpConnectResult> {
        let addr = SocketAddr::new(target, port);
        let timeout_duration = Duration::from_millis(self.config.timeout_ms);
        let start = std::time::Instant::now();

        match timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                let elapsed = start.elapsed();
                debug!("Port {}:{} is OPEN", target, port);

                // Try to grab banner (first few bytes of response)
                let banner = self.grab_banner(&mut stream).await;

                Ok(TcpConnectResult {
                    target,
                    port,
                    status: PortStatus::Open,
                    response_time_ms: Some(elapsed.as_millis() as u64),
                    banner,
                })
            }
            Ok(Err(e)) => {
                // Connection refused = port is closed
                debug!("Port {}:{} is CLOSED: {}", target, port, e);
                
                Ok(TcpConnectResult {
                    target,
                    port,
                    status: PortStatus::Closed,
                    response_time_ms: None,
                    banner: None,
                })
            }
            Err(_) => {
                // Timeout = port is filtered or host is down
                debug!("Port {}:{} is FILTERED (timeout)", target, port);
                
                Ok(TcpConnectResult {
                    target,
                    port,
                    status: PortStatus::Filtered,
                    response_time_ms: None,
                    banner: None,
                })
            }
        }
    }

    /// Attempt to grab service banner from an open connection
    async fn grab_banner(&self, stream: &mut TcpStream) -> Option<String> {
        use tokio::io::AsyncReadExt;

        let mut buffer = vec![0u8; 512];
        let read_timeout = Duration::from_millis(1000);

        match timeout(read_timeout, stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                let banner = String::from_utf8_lossy(&buffer[..n])
                    .trim()
                    .to_string();
                
                if !banner.is_empty() {
                    debug!("Grabbed banner: {}", banner.chars().take(50).collect::<String>());
                    return Some(banner);
                }
            }
            _ => {
                // No banner or timeout
            }
        }

        None
    }

    /// Scan multiple ports on a single host
    /// 
    /// # Arguments
    /// * `target` - IP address to scan
    /// * `ports` - Vector of port numbers to scan
    /// * `max_concurrent` - Maximum number of concurrent scans
    /// 
    /// # Returns
    /// * `ScanResult<Vec<TcpConnectResult>>` - Scan results for all ports
    pub async fn scan_ports(
        &self,
        target: IpAddr,
        ports: Vec<u16>,
        max_concurrent: usize,
    ) -> ScanResult<Vec<TcpConnectResult>> {
        use futures::stream::{self, StreamExt};

        info!(
            "TCP connect scan: {} ports on {} with concurrency {}",
            ports.len(),
            target,
            max_concurrent
        );

        let results = stream::iter(ports)
            .map(|port| async move {
                match self.scan_port(target, port).await {
                    Ok(result) => Some(result),
                    Err(e) => {
                        warn!("Scan failed for {}:{} - {}", target, port, e);
                        None
                    }
                }
            })
            .buffer_unordered(max_concurrent)
            .collect::<Vec<_>>()
            .await;

        let results: Vec<TcpConnectResult> = results.into_iter().flatten().collect();
        
        let open_count = results
            .iter()
            .filter(|r| r.status == PortStatus::Open)
            .count();
        
        info!(
            "TCP connect scan complete: {}/{} ports open on {}",
            open_count,
            results.len(),
            target
        );

        Ok(results)
    }

    /// Scan a port range on a target host
    /// 
    /// # Arguments
    /// * `target` - IP address to scan
    /// * `start_port` - Starting port number
    /// * `end_port` - Ending port number (inclusive)
    /// * `max_concurrent` - Maximum number of concurrent scans
    /// 
    /// # Returns
    /// * `ScanResult<Vec<TcpConnectResult>>` - Scan results for the port range
    pub async fn scan_port_range(
        &self,
        target: IpAddr,
        start_port: u16,
        end_port: u16,
        max_concurrent: usize,
    ) -> ScanResult<Vec<TcpConnectResult>> {
        if start_port > end_port {
            return Err(ScanError::InvalidPortRange {
                start: start_port,
                end: end_port,
            });
        }

        let ports: Vec<u16> = (start_port..=end_port).collect();
        self.scan_ports(target, ports, max_concurrent).await
    }
}

impl std::fmt::Display for PortStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortStatus::Open => write!(f, "open"),
            PortStatus::Closed => write!(f, "closed"),
            PortStatus::Filtered => write!(f, "filtered"),
            PortStatus::Unknown => write!(f, "unknown"),
        }
    }
}

impl std::fmt::Display for TcpConnectResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} - {} ({}ms)",
            self.target,
            self.port,
            self.status,
            self.response_time_ms
                .map_or("N/A".to_string(), |t| t.to_string())
        )?;
        
        if let Some(ref banner) = self.banner {
            write!(f, " [{}]", banner.chars().take(30).collect::<String>())?;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn create_test_config() -> TcpConnectConfig {
        TcpConnectConfig {
            enabled: true,
            timeout_ms: 2000,
            retries: 1,
            retry_delay_ms: 100,
        }
    }

    #[tokio::test]
    async fn test_tcp_scanner_creation() {
        let config = create_test_config();
        let _scanner = TcpConnectScanner::new(config);
    }

    #[tokio::test]
    async fn test_scan_disabled() {
        let mut config = create_test_config();
        config.enabled = false;
        let scanner = TcpConnectScanner::new(config);
        
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = scanner.scan_port(target, 80).await;
        
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_port_range() {
        let config = create_test_config();
        let scanner = TcpConnectScanner::new(config);
        
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = scanner.scan_port_range(target, 100, 50, 10).await;
        
        assert!(result.is_err());
    }

    #[test]
    fn test_port_status_display() {
        assert_eq!(format!("{}", PortStatus::Open), "open");
        assert_eq!(format!("{}", PortStatus::Closed), "closed");
        assert_eq!(format!("{}", PortStatus::Filtered), "filtered");
        assert_eq!(format!("{}", PortStatus::Unknown), "unknown");
    }

    // Note: More comprehensive tests would require a test server
    // or mocking the network layer
}

