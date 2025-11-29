/// Scanner module - orchestrates all scanning operations
/// 
/// This module provides the main scanner interface that coordinates
/// host discovery, port scanning, and adaptive throttling.

pub mod host_discovery;
pub mod tcp_connect;
pub mod tcp_syn;
pub mod udp_scan;
pub mod throttle;

use crate::config::ScannerConfig;
use host_discovery::{HostDiscovery, HostStatus};
use tcp_connect::{PortStatus, TcpConnectResult, TcpConnectScanner};
use tcp_syn::{TcpSynResult, TcpSynScanner};
use udp_scan::{UdpScanResult, UdpScanner};
use throttle::{AdaptiveThrottle, ThrottleStats};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{info, warn};
use serde::{Deserialize, Serialize};

/// Scan type selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanType {
    TcpConnect,
    TcpSyn,
    Udp,
}

/// Comprehensive scan result combining all scan types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteScanResult {
    pub target: IpAddr,
    pub host_status: HostStatus,
    pub tcp_results: Vec<TcpConnectResult>,
    pub syn_results: Vec<TcpSynResult>,
    pub udp_results: Vec<UdpScanResult>,
    pub scan_duration_ms: u64,
    pub throttle_stats: Option<ThrottleStats>,
}

/// Main scanner orchestrator
pub struct Scanner {
    config: ScannerConfig,
    host_discovery: HostDiscovery,
    tcp_scanner: TcpConnectScanner,
    syn_scanner: TcpSynScanner,
    udp_scanner: UdpScanner,
    throttle: Option<Arc<AdaptiveThrottle>>,
}

impl Scanner {
    /// Create a new scanner with configuration
    pub fn new(config: ScannerConfig) -> Self {
        info!("Initializing scanner with configuration");

        let throttle = if config.adaptive_throttling {
            Some(Arc::new(AdaptiveThrottle::new(
                crate::config::ThrottlingConfig {
                    enabled: true,
                    success_threshold: 0.95,
                    failure_threshold: 0.80,
                    rate_increase_factor: 1.5,
                    rate_decrease_factor: 0.5,
                    window_size: 100,
                    adjustment_interval_ms: 1000,
                },
                config.initial_pps,
            )))
        } else {
            None
        };

        Self {
            host_discovery: HostDiscovery::new(config.host_discovery.clone()),
            tcp_scanner: TcpConnectScanner::new(config.tcp_connect.clone()),
            syn_scanner: TcpSynScanner::new(config.tcp_syn.clone()),
            udp_scanner: UdpScanner::new(config.udp.clone()),
            throttle,
            config,
        }
    }

    /// Perform a comprehensive scan on a target
    /// 
    /// # Arguments
    /// * `target` - IP address to scan
    /// * `ports` - Vector of port numbers to scan
    /// * `scan_types` - Types of scans to perform
    /// 
    /// # Returns
    /// * `crate::error::ScanResult<CompleteScanResult>` - Comprehensive scan results
    pub async fn scan(
        &self,
        target: IpAddr,
        ports: Vec<u16>,
        scan_types: Vec<ScanType>,
    ) -> crate::error::ScanResult<CompleteScanResult> {
        let start = std::time::Instant::now();
        info!("Starting scan on {} for {} ports", target, ports.len());

        // Step 1: Host discovery
        let host_status = match self.host_discovery.discover(target).await {
            Ok(result) => {
                if result.status == HostStatus::Down {
                    warn!("Host {} appears to be down, continuing with scan anyway", target);
                }
                result.status
            }
            Err(e) => {
                warn!("Host discovery failed: {}, assuming host is up", e);
                HostStatus::Unknown
            }
        };

        // Step 2: Port scanning based on requested scan types
        let mut tcp_results = Vec::new();
        let mut syn_results = Vec::new();
        let mut udp_results = Vec::new();

        for scan_type in scan_types {
            match scan_type {
                ScanType::TcpConnect => {
                    info!("Performing TCP connect scan");
                    match self.tcp_scanner.scan_ports(
                        target,
                        ports.clone(),
                        self.config.max_concurrent_scans,
                    ).await {
                        Ok(results) => tcp_results = results,
                        Err(e) => warn!("TCP connect scan failed: {}", e),
                    }
                }
                ScanType::TcpSyn => {
                    info!("Performing TCP SYN scan");
                    match self.syn_scanner.scan_ports(
                        target,
                        ports.clone(),
                        self.config.max_concurrent_scans,
                    ).await {
                        Ok(results) => syn_results = results,
                        Err(e) => warn!("TCP SYN scan failed: {}", e),
                    }
                }
                ScanType::Udp => {
                    info!("Performing UDP scan");
                    match self.udp_scanner.scan_ports(
                        target,
                        ports.clone(),
                        self.config.max_concurrent_scans,
                    ).await {
                        Ok(results) => udp_results = results,
                        Err(e) => warn!("UDP scan failed: {}", e),
                    }
                }
            }
        }

        let elapsed = start.elapsed();
        let throttle_stats = if let Some(ref throttle) = self.throttle {
            Some(throttle.get_stats().await)
        } else {
            None
        };

        info!(
            "Scan completed for {} in {}ms",
            target,
            elapsed.as_millis()
        );

        Ok(CompleteScanResult {
            target,
            host_status,
            tcp_results,
            syn_results,
            udp_results,
            scan_duration_ms: elapsed.as_millis() as u64,
            throttle_stats,
        })
    }

    /// Scan multiple targets
    /// 
    /// # Arguments
    /// * `targets` - Vector of IP addresses to scan
    /// * `ports` - Vector of port numbers to scan
    /// * `scan_types` - Types of scans to perform
    /// 
    /// # Returns
    /// * `crate::error::ScanResult<Vec<CompleteScanResult>>` - Scan results for all targets
    pub async fn scan_multiple(
        &self,
        targets: Vec<IpAddr>,
        ports: Vec<u16>,
        scan_types: Vec<ScanType>,
    ) -> crate::error::ScanResult<Vec<CompleteScanResult>> {
        use futures::stream::{self, StreamExt};

        info!(
            "Starting scan on {} targets, {} ports per target",
            targets.len(),
            ports.len()
        );

        let ports_clone = ports.clone();
        let scan_types_clone = scan_types.clone();

        let results = stream::iter(targets)
            .map(|target| {
                let ports_ref = ports_clone.clone();
                let scan_types_ref = scan_types_clone.clone();
                async move {
                    match self.scan(target, ports_ref, scan_types_ref).await {
                        Ok(result) => Some(result),
                        Err(e) => {
                            warn!("Scan failed for {}: {}", target, e);
                            None
                        }
                    }
                }
            })
            .buffer_unordered(10) // Limit concurrent target scans
            .collect::<Vec<_>>()
            .await;

        let results: Vec<CompleteScanResult> = results.into_iter().flatten().collect();
        
        info!("Completed scans on {} targets", results.len());

        Ok(results)
    }

    /// Get current throttle statistics (if throttling is enabled)
    pub async fn get_throttle_stats(&self) -> Option<ThrottleStats> {
        if let Some(ref throttle) = self.throttle {
            Some(throttle.get_stats().await)
        } else {
            None
        }
    }
}

impl std::fmt::Display for CompleteScanResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Scan Results for {}", self.target)?;
        writeln!(f, "  Host Status: {}", self.host_status)?;
        writeln!(f, "  Scan Duration: {}ms", self.scan_duration_ms)?;
        
        if !self.tcp_results.is_empty() {
            writeln!(f, "\n  TCP Connect Results:")?;
            for result in &self.tcp_results {
                if result.status == PortStatus::Open {
                    writeln!(f, "    {}", result)?;
                }
            }
        }
        
        if !self.syn_results.is_empty() {
            writeln!(f, "\n  TCP SYN Results:")?;
            for result in &self.syn_results {
                if result.status == PortStatus::Open {
                    writeln!(f, "    {}", result)?;
                }
            }
        }
        
        if !self.udp_results.is_empty() {
            writeln!(f, "\n  UDP Results:")?;
            for result in &self.udp_results {
                if result.status == PortStatus::Open {
                    writeln!(f, "    {}", result)?;
                }
            }
        }
        
        if let Some(ref stats) = self.throttle_stats {
            writeln!(f, "\n  {}", stats)?;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> ScannerConfig {
        use crate::config::*;
        
        ScannerConfig {
            default_timeout_ms: 2000,
            max_concurrent_scans: 100,
            adaptive_throttling: false,
            initial_pps: 1000,
            max_pps: 10000,
            min_pps: 100,
            host_discovery: HostDiscoveryConfig {
                enabled: false,
                method: "tcp".to_string(),
                timeout_ms: 1000,
                retries: 1,
            },
            tcp_connect: crate::config::TcpConnectConfig {
                enabled: true,
                timeout_ms: 2000,
                retries: 1,
                retry_delay_ms: 100,
            },
            tcp_syn: crate::config::TcpSynConfig {
                enabled: false,
                timeout_ms: 2000,
                retries: 1,
                retry_delay_ms: 50,
            },
            udp: crate::config::UdpConfig {
                enabled: false,
                timeout_ms: 2000,
                retries: 1,
                retry_delay_ms: 200,
            },
        }
    }

    #[test]
    fn test_scanner_creation() {
        let config = create_test_config();
        let _scanner = Scanner::new(config);
    }

    #[test]
    fn test_scan_type_equality() {
        assert_eq!(ScanType::TcpConnect, ScanType::TcpConnect);
        assert_ne!(ScanType::TcpConnect, ScanType::Udp);
    }
}

