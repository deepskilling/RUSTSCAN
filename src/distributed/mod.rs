/// Distributed scanning module for NrMAP
/// 
/// This module provides distributed scanning capabilities including job scheduling,
/// agent-based scanning, and result aggregation across multiple nodes.

pub mod scheduler;
pub mod agent;
pub mod aggregator;

pub use scheduler::{ScanScheduler, ScanJob, JobStatus};
pub use agent::{ScanAgent, AgentConfig, AgentStatus};
pub use aggregator::{ResultAggregator, AggregatedResults};

use crate::error::ScanResult;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::info;

/// Distributed scanning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedConfig {
    pub enable_distributed: bool,
    pub scheduler_port: u16,
    pub agent_port: u16,
    pub max_agents: usize,
    pub job_timeout_seconds: u64,
    pub result_retention_hours: u64,
}

impl Default for DistributedConfig {
    fn default() -> Self {
        Self {
            enable_distributed: false,
            scheduler_port: 8080,
            agent_port: 8081,
            max_agents: 10,
            job_timeout_seconds: 3600,
            result_retention_hours: 24,
        }
    }
}

/// Distributed scanner coordinator
pub struct DistributedScanner {
    config: DistributedConfig,
    scheduler: ScanScheduler,
    aggregator: ResultAggregator,
}

impl DistributedScanner {
    /// Create a new distributed scanner
    pub fn new(config: DistributedConfig) -> ScanResult<Self> {
        info!("Initializing distributed scanner");
        
        let scheduler = ScanScheduler::new(
            config.max_agents,
            config.job_timeout_seconds,
        );
        
        let aggregator = ResultAggregator::new(
            config.result_retention_hours,
        );
        
        Ok(Self {
            config,
            scheduler,
            aggregator,
        })
    }

    /// Submit a scan job for distributed execution
    pub async fn submit_job(
        &mut self,
        targets: Vec<IpAddr>,
        ports: Vec<u16>,
    ) -> ScanResult<String> {
        self.scheduler.submit_job(targets, ports).await
    }

    /// Get job status
    pub async fn get_job_status(&self, job_id: &str) -> ScanResult<Option<JobStatus>> {
        self.scheduler.get_job_status(job_id).await
    }

    /// Get aggregated results for a job
    pub async fn get_results(&self, job_id: &str) -> ScanResult<Option<AggregatedResults>> {
        self.aggregator.get_results(job_id).await
    }

    /// Register a new agent
    pub async fn register_agent(&mut self, agent_id: String, address: String) -> ScanResult<()> {
        self.scheduler.register_agent(agent_id, address).await
    }

    /// Get distributed configuration
    pub fn config(&self) -> &DistributedConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distributed_config_default() {
        let config = DistributedConfig::default();
        assert_eq!(config.scheduler_port, 8080);
        assert_eq!(config.agent_port, 8081);
        assert!(!config.enable_distributed);
    }

    #[test]
    fn test_distributed_scanner_creation() {
        let config = DistributedConfig::default();
        let result = DistributedScanner::new(config);
        assert!(result.is_ok());
    }
}

