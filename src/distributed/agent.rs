/// Scan agent for distributed scanning
/// 
/// This module implements the agent side of distributed scanning, which receives
/// scan jobs from the scheduler, executes them, and reports results back.

use crate::error::ScanResult;
use crate::scanner::{Scanner, ScanType};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub agent_id: String,
    pub scheduler_address: String,
    pub listen_address: String,
    pub heartbeat_interval_seconds: u64,
    pub max_concurrent_jobs: usize,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id: format!("agent-{}", uuid::Uuid::new_v4()),
            scheduler_address: "127.0.0.1:8080".to_string(),
            listen_address: "0.0.0.0:8081".to_string(),
            heartbeat_interval_seconds: 30,
            max_concurrent_jobs: 1,
        }
    }
}

/// Agent status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStatus {
    Initializing,
    Ready,
    Busy,
    Error,
    Shutdown,
}

impl std::fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentStatus::Initializing => write!(f, "Initializing"),
            AgentStatus::Ready => write!(f, "Ready"),
            AgentStatus::Busy => write!(f, "Busy"),
            AgentStatus::Error => write!(f, "Error"),
            AgentStatus::Shutdown => write!(f, "Shutdown"),
        }
    }
}

/// Scan agent
pub struct ScanAgent {
    config: AgentConfig,
    status: Arc<RwLock<AgentStatus>>,
    scanner: Scanner,
    current_job: Arc<RwLock<Option<String>>>,
}

impl ScanAgent {
    /// Create a new scan agent
    /// 
    /// # Arguments
    /// * `config` - Agent configuration
    /// * `scanner_config` - Scanner configuration for actual scanning
    pub fn new(config: AgentConfig, scanner_config: crate::config::ScannerConfig) -> ScanResult<Self> {
        info!("Initializing scan agent: {}", config.agent_id);
        
        let scanner = Scanner::new(scanner_config);
        
        Ok(Self {
            config,
            status: Arc::new(RwLock::new(AgentStatus::Initializing)),
            scanner,
            current_job: Arc::new(RwLock::new(None)),
        })
    }

    /// Start the agent
    /// 
    /// This will register with the scheduler and start listening for jobs
    pub async fn start(&mut self) -> ScanResult<()> {
        info!("Starting agent: {}", self.config.agent_id);
        
        // Register with scheduler
        self.register_with_scheduler().await?;
        
        // Set status to ready
        let mut status = self.status.write().await;
        *status = AgentStatus::Ready;
        drop(status);
        
        info!("Agent {} is ready", self.config.agent_id);
        
        // Start heartbeat task
        self.start_heartbeat_task();
        
        Ok(())
    }

    /// Register with the scheduler
    async fn register_with_scheduler(&self) -> ScanResult<()> {
        info!(
            "Registering with scheduler at {}",
            self.config.scheduler_address
        );
        
        // TODO: Implement actual HTTP/gRPC registration
        // For now, this is a framework implementation
        debug!("Agent registration (framework mode)");
        
        Ok(())
    }

    /// Start heartbeat task
    fn start_heartbeat_task(&self) {
        let agent_id = self.config.agent_id.clone();
        let scheduler_address = self.config.scheduler_address.clone();
        let interval = self.config.heartbeat_interval_seconds;
        
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
                
                // TODO: Send heartbeat to scheduler
                debug!("Heartbeat: {} -> {}", agent_id, scheduler_address);
            }
        });
    }

    /// Execute a scan job
    /// 
    /// # Arguments
    /// * `job_id` - Job identifier
    /// * `targets` - Targets to scan
    /// * `ports` - Ports to scan
    /// * `scan_types` - Types of scans to perform
    pub async fn execute_job(
        &mut self,
        job_id: String,
        targets: Vec<IpAddr>,
        ports: Vec<u16>,
        scan_types: Vec<ScanType>,
    ) -> ScanResult<Vec<crate::scanner::CompleteScanResult>> {
        info!(
            "Executing job {}: {} targets, {} ports",
            job_id,
            targets.len(),
            ports.len()
        );
        
        // Set status to busy
        {
            let mut status = self.status.write().await;
            *status = AgentStatus::Busy;
        }
        
        // Set current job
        {
            let mut current_job = self.current_job.write().await;
            *current_job = Some(job_id.clone());
        }
        
        // Execute the scan
        let result = self.scanner
            .scan_multiple(targets, ports, scan_types)
            .await;
        
        // Clear current job
        {
            let mut current_job = self.current_job.write().await;
            *current_job = None;
        }
        
        // Set status back to ready
        {
            let mut status = self.status.write().await;
            *status = AgentStatus::Ready;
        }
        
        match result {
            Ok(results) => {
                info!("Job {} completed successfully: {} results", job_id, results.len());
                Ok(results)
            }
            Err(e) => {
                error!("Job {} failed: {}", job_id, e);
                Err(e)
            }
        }
    }

    /// Get agent status
    pub async fn get_status(&self) -> AgentStatus {
        *self.status.read().await
    }

    /// Get current job
    pub async fn get_current_job(&self) -> Option<String> {
        self.current_job.read().await.clone()
    }

    /// Get agent ID
    pub fn agent_id(&self) -> &str {
        &self.config.agent_id
    }

    /// Shutdown the agent
    pub async fn shutdown(&mut self) -> ScanResult<()> {
        info!("Shutting down agent: {}", self.config.agent_id);
        
        // Check if there's a current job
        let current_job = self.get_current_job().await;
        if current_job.is_some() {
            warn!("Agent shutting down with active job");
        }
        
        // Set status to shutdown
        let mut status = self.status.write().await;
        *status = AgentStatus::Shutdown;
        
        // TODO: Unregister from scheduler
        debug!("Agent unregistration (framework mode)");
        
        info!("Agent {} shut down", self.config.agent_id);
        Ok(())
    }

    /// Get agent statistics
    pub async fn get_stats(&self) -> AgentStats {
        let status = self.get_status().await;
        let current_job = self.get_current_job().await;
        
        AgentStats {
            agent_id: self.config.agent_id.clone(),
            status,
            current_job,
            scheduler_address: self.config.scheduler_address.clone(),
        }
    }
}

/// Agent statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStats {
    pub agent_id: String,
    pub status: AgentStatus,
    pub current_job: Option<String>,
    pub scheduler_address: String,
}

impl std::fmt::Display for AgentStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Agent Statistics:")?;
        writeln!(f, "  ID: {}", self.agent_id)?;
        writeln!(f, "  Status: {}", self.status)?;
        writeln!(f, "  Scheduler: {}", self.scheduler_address)?;
        if let Some(ref job) = self.current_job {
            writeln!(f, "  Current Job: {}", job)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScannerConfig;

    fn create_test_config() -> AgentConfig {
        AgentConfig {
            agent_id: "test-agent".to_string(),
            scheduler_address: "127.0.0.1:8080".to_string(),
            listen_address: "0.0.0.0:8081".to_string(),
            heartbeat_interval_seconds: 30,
            max_concurrent_jobs: 1,
        }
    }

    fn create_test_scanner_config() -> ScannerConfig {
        use crate::config::*;
        
        ScannerConfig {
            default_timeout_ms: 1000,
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
            tcp_connect: TcpConnectConfig {
                enabled: true,
                timeout_ms: 1000,
                retries: 1,
                retry_delay_ms: 100,
            },
            tcp_syn: TcpSynConfig {
                enabled: false,
                timeout_ms: 1000,
                retries: 1,
                retry_delay_ms: 50,
            },
            udp: UdpConfig {
                enabled: false,
                timeout_ms: 1000,
                retries: 1,
                retry_delay_ms: 200,
            },
        }
    }

    #[test]
    fn test_agent_config_default() {
        let config = AgentConfig::default();
        assert!(config.agent_id.starts_with("agent-"));
        assert_eq!(config.heartbeat_interval_seconds, 30);
    }

    #[test]
    fn test_agent_creation() {
        let agent_config = create_test_config();
        let scanner_config = create_test_scanner_config();
        
        let result = ScanAgent::new(agent_config, scanner_config);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_agent_status() {
        let agent_config = create_test_config();
        let scanner_config = create_test_scanner_config();
        
        let agent = ScanAgent::new(agent_config, scanner_config).unwrap();
        let status = agent.get_status().await;
        
        assert_eq!(status, AgentStatus::Initializing);
    }

    #[test]
    fn test_agent_status_display() {
        assert_eq!(format!("{}", AgentStatus::Ready), "Ready");
        assert_eq!(format!("{}", AgentStatus::Busy), "Busy");
        assert_eq!(format!("{}", AgentStatus::Shutdown), "Shutdown");
    }
}

