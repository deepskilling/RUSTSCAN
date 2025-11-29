/// UDP scan module for NrMAP
/// 
/// This module implements UDP port scanning. UDP scanning is challenging
/// because UDP is connectionless and many services don't respond to probes.
/// The scanner uses timeouts and ICMP port unreachable messages to detect closed ports.

use crate::config::UdpConfig;
use crate::error::{ScanError, ScanResult};
use crate::scanner::tcp_connect::PortStatus;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// UDP scan result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UdpScanResult {
    pub target: IpAddr,
    pub port: u16,
    pub status: PortStatus,
    pub response_time_ms: Option<u64>,
    pub response_data: Option<Vec<u8>>,
}

/// UDP scanner
/// 
/// UDP scanning is inherently unreliable:
/// - Open|Filtered: No response or any response (can't distinguish without ICMP)
/// - Closed: ICMP port unreachable (requires raw socket to detect)
/// - Open: Only if service responds to our probe
pub struct UdpScanner {
    config: UdpConfig,
}

impl UdpScanner {
    /// Create a new UDP scanner
    pub fn new(config: UdpConfig) -> Self {
        info!(
            "Initializing UDP scanner: timeout={}ms, retries={}",
            config.timeout_ms, config.retries
        );
        Self { config }
    }

    /// Scan a single UDP port on a target host
    /// 
    /// # Arguments
    /// * `target` - IP address to scan
    /// * `port` - Port number to scan
    /// 
    /// # Returns
    /// * `ScanResult<UdpScanResult>` - Scan result with port status
    pub async fn scan_port(&self, target: IpAddr, port: u16) -> ScanResult<UdpScanResult> {
        if !self.config.enabled {
            return Err(ScanError::scanner_error("UDP scan is disabled"));
        }

        debug!("UDP scan: {}:{}", target, port);

        let start = std::time::Instant::now();

        // Attempt scan with retries
        for attempt in 0..=self.config.retries {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(self.config.retry_delay_ms)).await;
                debug!("Retrying UDP scan {}:{} (attempt {})", target, port, attempt + 1);
            }

            match self.try_udp_probe(target, port).await {
                Ok(result) => {
                    let elapsed = start.elapsed();
                    crate::log_scan_event!(
                        tracing::Level::INFO,
                        target,
                        port,
                        result.status.to_string(),
                        format!("UDP scan completed in {}ms", elapsed.as_millis())
                    );
                    return Ok(result);
                }
                Err(_e) => {
                    continue;
                }
            }
        }

        // All retries failed - for UDP this often means open|filtered
        // Return a result indicating uncertain status rather than an error
        Ok(UdpScanResult {
            target,
            port,
            status: PortStatus::Filtered,
            response_time_ms: None,
            response_data: None,
        })
    }

    /// Attempt a single UDP probe
    async fn try_udp_probe(&self, target: IpAddr, port: u16) -> ScanResult<UdpScanResult> {
        // Bind to a local UDP socket
        let local_addr = match target {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };

        let socket = UdpSocket::bind(local_addr).await.map_err(|e| {
            ScanError::udp_scan_failed(target, port, format!("Failed to bind socket: {}", e))
        })?;

        let target_addr = SocketAddr::new(target, port);
        let timeout_duration = Duration::from_millis(self.config.timeout_ms);
        let start = std::time::Instant::now();

        // Send UDP probe packet
        // For better results, we should send service-specific probes
        let probe = self.create_probe_packet(port);
        
        socket.send_to(&probe, target_addr).await.map_err(|e| {
            ScanError::udp_scan_failed(target, port, format!("Failed to send probe: {}", e))
        })?;

        debug!("Sent UDP probe to {}:{}", target, port);

        // Try to receive a response
        let mut buffer = vec![0u8; 4096];
        
        match timeout(timeout_duration, socket.recv_from(&mut buffer)).await {
            Ok(Ok((len, _addr))) => {
                let elapsed = start.elapsed();
                debug!("UDP port {}:{} responded with {} bytes", target, port, len);
                
                Ok(UdpScanResult {
                    target,
                    port,
                    status: PortStatus::Open,
                    response_time_ms: Some(elapsed.as_millis() as u64),
                    response_data: Some(buffer[..len].to_vec()),
                })
            }
            Ok(Err(e)) => {
                // Check if we got ICMP port unreachable (ConnectionRefused)
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    debug!("UDP port {}:{} is CLOSED (ICMP port unreachable)", target, port);
                    Ok(UdpScanResult {
                        target,
                        port,
                        status: PortStatus::Closed,
                        response_time_ms: None,
                        response_data: None,
                    })
                } else {
                    Err(ScanError::udp_scan_failed(
                        target,
                        port,
                        format!("Socket error: {}", e),
                    ))
                }
            }
            Err(_) => {
                // Timeout - port is open|filtered (can't determine without ICMP)
                debug!("UDP port {}:{} is OPEN|FILTERED (no response)", target, port);
                Ok(UdpScanResult {
                    target,
                    port,
                    status: PortStatus::Filtered,
                    response_time_ms: None,
                    response_data: None,
                })
            }
        }
    }

    /// Create a service-specific probe packet
    /// 
    /// Different UDP services respond to different probes.
    /// This method returns appropriate probe data based on the port number.
    fn create_probe_packet(&self, port: u16) -> Vec<u8> {
        match port {
            53 => {
                // DNS query for "version.bind" (common DNS probe)
                vec![
                    0x00, 0x00, // Transaction ID
                    0x01, 0x00, // Flags: standard query
                    0x00, 0x01, // Questions: 1
                    0x00, 0x00, // Answer RRs: 0
                    0x00, 0x00, // Authority RRs: 0
                    0x00, 0x00, // Additional RRs: 0
                    // Query: version.bind
                    0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
                    0x04, 0x62, 0x69, 0x6e, 0x64,
                    0x00, // End of name
                    0x00, 0x10, // Type: TXT
                    0x00, 0x03, // Class: CHAOS
                ]
            }
            123 => {
                // NTP query
                vec![
                    0x1b, // LI, Version, Mode
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ]
            }
            161 => {
                // SNMP GetRequest
                vec![
                    0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
                    0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
                    0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00,
                    0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06,
                    0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00,
                ]
            }
            _ => {
                // Generic probe - empty packet or minimal data
                // Some services respond to any data
                vec![0x00, 0x00]
            }
        }
    }

    /// Scan multiple ports on a single host using UDP
    /// 
    /// # Arguments
    /// * `target` - IP address to scan
    /// * `ports` - Vector of port numbers to scan
    /// * `max_concurrent` - Maximum number of concurrent scans
    /// 
    /// # Returns
    /// * `ScanResult<Vec<UdpScanResult>>` - Scan results for all ports
    pub async fn scan_ports(
        &self,
        target: IpAddr,
        ports: Vec<u16>,
        max_concurrent: usize,
    ) -> ScanResult<Vec<UdpScanResult>> {
        use futures::stream::{self, StreamExt};

        info!(
            "UDP scan: {} ports on {} with concurrency {}",
            ports.len(),
            target,
            max_concurrent
        );

        let results = stream::iter(ports)
            .map(|port| async move {
                match self.scan_port(target, port).await {
                    Ok(result) => Some(result),
                    Err(e) => {
                        warn!("UDP scan failed for {}:{} - {}", target, port, e);
                        None
                    }
                }
            })
            .buffer_unordered(max_concurrent)
            .collect::<Vec<_>>()
            .await;

        let results: Vec<UdpScanResult> = results.into_iter().flatten().collect();
        
        let open_count = results
            .iter()
            .filter(|r| r.status == PortStatus::Open)
            .count();
        
        let filtered_count = results
            .iter()
            .filter(|r| r.status == PortStatus::Filtered)
            .count();
        
        info!(
            "UDP scan complete: {} open, {} open|filtered out of {} ports on {}",
            open_count,
            filtered_count,
            results.len(),
            target
        );

        Ok(results)
    }

    /// Scan a port range on a target host using UDP
    pub async fn scan_port_range(
        &self,
        target: IpAddr,
        start_port: u16,
        end_port: u16,
        max_concurrent: usize,
    ) -> ScanResult<Vec<UdpScanResult>> {
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

impl std::fmt::Display for UdpScanResult {
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
        
        if let Some(ref data) = self.response_data {
            write!(f, " [{} bytes]", data.len())?;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn create_test_config() -> UdpConfig {
        UdpConfig {
            enabled: true,
            timeout_ms: 2000,
            retries: 2,
            retry_delay_ms: 200,
        }
    }

    #[test]
    fn test_udp_scanner_creation() {
        let config = create_test_config();
        let _scanner = UdpScanner::new(config);
    }

    #[test]
    fn test_probe_packet_creation() {
        let config = create_test_config();
        let scanner = UdpScanner::new(config);
        
        // DNS probe
        let dns_probe = scanner.create_probe_packet(53);
        assert!(!dns_probe.is_empty());
        
        // NTP probe
        let ntp_probe = scanner.create_probe_packet(123);
        assert!(!ntp_probe.is_empty());
        
        // Generic probe
        let generic_probe = scanner.create_probe_packet(9999);
        assert!(!generic_probe.is_empty());
    }

    #[tokio::test]
    async fn test_scan_disabled() {
        let mut config = create_test_config();
        config.enabled = false;
        let scanner = UdpScanner::new(config);
        
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = scanner.scan_port(target, 53).await;
        
        assert!(result.is_err());
    }

    // Note: More comprehensive tests would require test servers
    // UDP testing is particularly challenging due to its unreliable nature
}

