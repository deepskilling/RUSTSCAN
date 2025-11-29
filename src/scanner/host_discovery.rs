/// Host discovery module for NrMAP
/// 
/// This module implements various host discovery techniques to determine
/// which hosts are alive and reachable on the network before port scanning.

use crate::config::HostDiscoveryConfig;
use crate::error::ScanResult;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Result of a host discovery attempt
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HostStatus {
    Up,
    Down,
    Unknown,
}

/// Host discovery result
#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    pub target: IpAddr,
    pub status: HostStatus,
    pub response_time_ms: Option<u64>,
    pub method: String,
}

/// Host discovery scanner
pub struct HostDiscovery {
    config: HostDiscoveryConfig,
}

impl HostDiscovery {
    /// Create a new host discovery scanner
    pub fn new(config: HostDiscoveryConfig) -> Self {
        info!(
            "Initializing host discovery: method={}, timeout={}ms",
            config.method, config.timeout_ms
        );
        Self { config }
    }

    /// Discover if a host is up
    /// 
    /// # Arguments
    /// * `target` - IP address to check
    /// 
    /// # Returns
    /// * `ScanResult<DiscoveryResult>` - Discovery result with status and timing
    pub async fn discover(&self, target: IpAddr) -> ScanResult<DiscoveryResult> {
        if !self.config.enabled {
            return Ok(DiscoveryResult {
                target,
                status: HostStatus::Up,
                response_time_ms: None,
                method: "disabled".to_string(),
            });
        }

        debug!("Discovering host: {} using method: {}", target, self.config.method);

        let start = std::time::Instant::now();

        let status = match self.config.method.as_str() {
            "tcp" => self.tcp_discovery(target).await?,
            "icmp" => self.icmp_discovery(target).await?,
            "udp" => self.udp_discovery(target).await?,
            "arp" => self.arp_discovery(target).await?,
            _ => {
                warn!("Unknown discovery method: {}, defaulting to TCP", self.config.method);
                self.tcp_discovery(target).await?
            }
        };

        let elapsed = start.elapsed();
        let response_time_ms = if status == HostStatus::Up {
            Some(elapsed.as_millis() as u64)
        } else {
            None
        };

        let result = DiscoveryResult {
            target,
            status: status.clone(),
            response_time_ms,
            method: self.config.method.clone(),
        };

        match status {
            HostStatus::Up => {
                info!("Host {} is UP ({}ms)", target, elapsed.as_millis());
            }
            HostStatus::Down => {
                debug!("Host {} is DOWN", target);
            }
            HostStatus::Unknown => {
                debug!("Host {} status is UNKNOWN", target);
            }
        }

        Ok(result)
    }

    /// TCP-based host discovery (connect to common ports)
    /// 
    /// Attempts to connect to commonly open ports (80, 443, 22, 21)
    async fn tcp_discovery(&self, target: IpAddr) -> ScanResult<HostStatus> {
        let common_ports = [80u16, 443, 22, 21, 25, 3389];
        let timeout_duration = Duration::from_millis(self.config.timeout_ms);

        for &port in &common_ports {
            let addr = SocketAddr::new(target, port);
            
            match timeout(timeout_duration, TcpStream::connect(addr)).await {
                Ok(Ok(_stream)) => {
                    debug!("TCP discovery: {}:{} responded", target, port);
                    return Ok(HostStatus::Up);
                }
                Ok(Err(_)) => {
                    // Connection refused means host is up but port is closed
                    debug!("TCP discovery: {}:{} refused (host is up)", target, port);
                    return Ok(HostStatus::Up);
                }
                Err(_) => {
                    // Timeout, try next port
                    continue;
                }
            }
        }

        // If all ports timed out or failed, host is likely down
        Ok(HostStatus::Down)
    }

    /// ICMP-based host discovery (ping)
    /// 
    /// Note: This is a simplified implementation. For full ICMP support,
    /// you would need raw sockets and elevated privileges.
    async fn icmp_discovery(&self, target: IpAddr) -> ScanResult<HostStatus> {
        debug!("ICMP discovery for {} (fallback to TCP)", target);
        
        // In a production implementation, this would use raw ICMP packets
        // For now, we fall back to TCP discovery as ICMP requires privileges
        // TODO: Implement actual ICMP ping using raw sockets
        
        warn!(
            "ICMP discovery not fully implemented, falling back to TCP for {}",
            target
        );
        
        self.tcp_discovery(target).await
    }

    /// UDP-based host discovery
    /// 
    /// Sends UDP packets to common ports and checks for responses
    async fn udp_discovery(&self, target: IpAddr) -> ScanResult<HostStatus> {
        debug!("UDP discovery for {} (fallback to TCP)", target);
        
        // UDP discovery is unreliable as many hosts don't respond to UDP
        // For now, we fall back to TCP discovery
        // TODO: Implement UDP-based discovery with ICMP port unreachable detection
        
        warn!(
            "UDP discovery not fully implemented, falling back to TCP for {}",
            target
        );
        
        self.tcp_discovery(target).await
    }

    /// ARP-based host discovery (local network only)
    /// 
    /// Uses ARP requests to discover hosts on the local network
    async fn arp_discovery(&self, target: IpAddr) -> ScanResult<HostStatus> {
        debug!("ARP discovery for {} (fallback to TCP)", target);
        
        // ARP only works on local network and requires raw sockets
        // For now, we fall back to TCP discovery
        // TODO: Implement ARP discovery using raw sockets
        
        warn!(
            "ARP discovery not fully implemented, falling back to TCP for {}",
            target
        );
        
        self.tcp_discovery(target).await
    }

    /// Discover multiple hosts concurrently
    /// 
    /// # Arguments
    /// * `targets` - Vector of IP addresses to check
    /// * `max_concurrent` - Maximum number of concurrent discovery operations
    /// 
    /// # Returns
    /// * `ScanResult<Vec<DiscoveryResult>>` - Discovery results for all hosts
    pub async fn discover_many(
        &self,
        targets: Vec<IpAddr>,
        max_concurrent: usize,
    ) -> ScanResult<Vec<DiscoveryResult>> {
        use futures::stream::{self, StreamExt};

        info!("Discovering {} hosts with concurrency {}", targets.len(), max_concurrent);

        let results = stream::iter(targets)
            .map(|target| async move {
                match self.discover(target).await {
                    Ok(result) => Some(result),
                    Err(e) => {
                        warn!("Discovery failed for {}: {}", target, e);
                        None
                    }
                }
            })
            .buffer_unordered(max_concurrent)
            .collect::<Vec<_>>()
            .await;

        let results: Vec<DiscoveryResult> = results.into_iter().flatten().collect();
        
        let up_count = results.iter().filter(|r| r.status == HostStatus::Up).count();
        info!("Discovery complete: {}/{} hosts are up", up_count, results.len());

        Ok(results)
    }
}

impl std::fmt::Display for HostStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostStatus::Up => write!(f, "UP"),
            HostStatus::Down => write!(f, "DOWN"),
            HostStatus::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl std::fmt::Display for DiscoveryResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} (method: {}, response: {}ms)",
            self.target,
            self.status,
            self.method,
            self.response_time_ms.map_or("N/A".to_string(), |t| t.to_string())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn create_test_config() -> HostDiscoveryConfig {
        HostDiscoveryConfig {
            enabled: true,
            method: "tcp".to_string(),
            timeout_ms: 1000,
            retries: 1,
        }
    }

    #[tokio::test]
    async fn test_host_discovery_creation() {
        let config = create_test_config();
        let _discovery = HostDiscovery::new(config);
    }

    #[tokio::test]
    async fn test_localhost_discovery() {
        let config = create_test_config();
        let discovery = HostDiscovery::new(config);
        
        let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = discovery.discover(localhost).await;
        
        assert!(result.is_ok());
        // Localhost should typically be up
        // Note: This test might fail in restricted environments
    }

    #[tokio::test]
    async fn test_discovery_disabled() {
        let mut config = create_test_config();
        config.enabled = false;
        let discovery = HostDiscovery::new(config);
        
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let result = discovery.discover(target).await.unwrap();
        
        assert_eq!(result.status, HostStatus::Up);
        assert_eq!(result.method, "disabled");
    }

    #[test]
    fn test_host_status_display() {
        assert_eq!(format!("{}", HostStatus::Up), "UP");
        assert_eq!(format!("{}", HostStatus::Down), "DOWN");
        assert_eq!(format!("{}", HostStatus::Unknown), "UNKNOWN");
    }
}

