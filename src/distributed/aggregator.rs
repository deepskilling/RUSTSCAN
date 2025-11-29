/// Result aggregator for distributed scanning
/// 
/// This module collects and aggregates scan results from multiple agents,
/// provides result queries, and handles result storage.

use crate::error::ScanResult;
use crate::scanner::CompleteScanResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Aggregated scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedResults {
    pub job_id: String,
    pub results: Vec<CompleteScanResult>,
    pub total_targets: usize,
    pub total_ports_scanned: usize,
    pub open_ports_found: usize,
    pub scan_duration_ms: u64,
    pub agent_count: usize,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl std::fmt::Display for AggregatedResults {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Aggregated Results for Job: {}", self.job_id)?;
        writeln!(f, "  Targets Scanned: {}", self.total_targets)?;
        writeln!(f, "  Ports Scanned: {}", self.total_ports_scanned)?;
        writeln!(f, "  Open Ports Found: {}", self.open_ports_found)?;
        writeln!(f, "  Duration: {}ms", self.scan_duration_ms)?;
        writeln!(f, "  Agents Used: {}", self.agent_count)?;
        writeln!(f, "  Created: {}", self.created_at.format("%Y-%m-%d %H:%M:%S"))?;
        Ok(())
    }
}

/// Result entry
#[derive(Debug, Clone)]
struct ResultEntry {
    #[allow(dead_code)]
    job_id: String,
    agent_id: String,
    results: Vec<CompleteScanResult>,
    #[allow(dead_code)]
    received_at: chrono::DateTime<chrono::Utc>,
}

/// Result aggregator
pub struct ResultAggregator {
    results: Arc<RwLock<HashMap<String, Vec<ResultEntry>>>>,
    aggregated: Arc<RwLock<HashMap<String, AggregatedResults>>>,
    retention_hours: u64,
}

impl ResultAggregator {
    /// Create a new result aggregator
    /// 
    /// # Arguments
    /// * `retention_hours` - How long to keep results (in hours)
    pub fn new(retention_hours: u64) -> Self {
        info!("Initializing result aggregator: retention={}h", retention_hours);
        
        Self {
            results: Arc::new(RwLock::new(HashMap::new())),
            aggregated: Arc::new(RwLock::new(HashMap::new())),
            retention_hours,
        }
    }

    /// Store scan results from an agent
    /// 
    /// # Arguments
    /// * `job_id` - Job identifier
    /// * `agent_id` - Agent that produced the results
    /// * `results` - Scan results
    pub async fn store_results(
        &mut self,
        job_id: String,
        agent_id: String,
        results: Vec<CompleteScanResult>,
    ) -> ScanResult<()> {
        info!(
            "Storing results: job={}, agent={}, {} results",
            job_id,
            agent_id,
            results.len()
        );

        let entry = ResultEntry {
            job_id: job_id.clone(),
            agent_id,
            results,
            received_at: chrono::Utc::now(),
        };

        let mut all_results = self.results.write().await;
        all_results
            .entry(job_id.clone())
            .or_insert_with(Vec::new)
            .push(entry);
        drop(all_results);

        // Trigger aggregation
        self.aggregate_job_results(&job_id).await?;

        Ok(())
    }

    /// Aggregate results for a job
    async fn aggregate_job_results(&mut self, job_id: &str) -> ScanResult<()> {
        debug!("Aggregating results for job {}", job_id);

        let results = self.results.read().await;
        let entries = match results.get(job_id) {
            Some(e) => e.clone(),
            None => return Ok(()),
        };
        drop(results);

        // Collect all results
        let mut all_scan_results = Vec::new();
        let mut agent_ids = std::collections::HashSet::new();
        let mut total_duration_ms = 0u64;

        for entry in entries {
            agent_ids.insert(entry.agent_id.clone());
            for result in entry.results {
                total_duration_ms += result.scan_duration_ms;
                all_scan_results.push(result);
            }
        }

        // Calculate statistics
        let total_targets = all_scan_results.len();
        let total_ports_scanned: usize = all_scan_results
            .iter()
            .map(|r| r.tcp_results.len() + r.syn_results.len() + r.udp_results.len())
            .sum();

        let open_ports_found: usize = all_scan_results
            .iter()
            .map(|r| {
                r.tcp_results
                    .iter()
                    .filter(|tcp| tcp.status == crate::scanner::tcp_connect::PortStatus::Open)
                    .count()
            })
            .sum();

        let aggregated = AggregatedResults {
            job_id: job_id.to_string(),
            results: all_scan_results,
            total_targets,
            total_ports_scanned,
            open_ports_found,
            scan_duration_ms: total_duration_ms / agent_ids.len().max(1) as u64,
            agent_count: agent_ids.len(),
            created_at: chrono::Utc::now(),
        };

        let mut agg = self.aggregated.write().await;
        agg.insert(job_id.to_string(), aggregated);

        info!(
            "Aggregated results for job {}: {} targets, {} open ports",
            job_id, total_targets, open_ports_found
        );

        Ok(())
    }

    /// Get aggregated results for a job
    /// 
    /// # Arguments
    /// * `job_id` - Job identifier
    /// 
    /// # Returns
    /// * `ScanResult<Option<AggregatedResults>>` - Aggregated results if available
    pub async fn get_results(&self, job_id: &str) -> ScanResult<Option<AggregatedResults>> {
        let agg = self.aggregated.read().await;
        Ok(agg.get(job_id).cloned())
    }

    /// Get results summary for a job
    pub async fn get_summary(&self, job_id: &str) -> ScanResult<Option<ResultSummary>> {
        let results = self.get_results(job_id).await?;
        
        Ok(results.map(|r| ResultSummary {
            job_id: r.job_id,
            total_targets: r.total_targets,
            total_ports_scanned: r.total_ports_scanned,
            open_ports_found: r.open_ports_found,
            scan_duration_ms: r.scan_duration_ms,
            agent_count: r.agent_count,
        }))
    }

    /// List all job IDs with results
    pub async fn list_jobs(&self) -> ScanResult<Vec<String>> {
        let agg = self.aggregated.read().await;
        Ok(agg.keys().cloned().collect())
    }

    /// Delete results for a job
    pub async fn delete_results(&mut self, job_id: &str) -> ScanResult<()> {
        let mut results = self.results.write().await;
        results.remove(job_id);
        
        let mut agg = self.aggregated.write().await;
        agg.remove(job_id);
        
        info!("Deleted results for job {}", job_id);
        Ok(())
    }

    /// Clean up old results based on retention policy
    pub async fn cleanup_old_results(&mut self) -> ScanResult<usize> {
        let cutoff = chrono::Utc::now() - chrono::Duration::hours(self.retention_hours as i64);
        let mut removed = 0;

        let agg = self.aggregated.read().await;
        let jobs_to_remove: Vec<String> = agg
            .iter()
            .filter(|(_, r)| r.created_at < cutoff)
            .map(|(id, _)| id.clone())
            .collect();
        drop(agg);

        for job_id in jobs_to_remove {
            self.delete_results(&job_id).await?;
            removed += 1;
        }

        if removed > 0 {
            info!("Cleaned up {} old result sets", removed);
        }

        Ok(removed)
    }

    /// Get aggregator statistics
    pub async fn get_stats(&self) -> AggregatorStats {
        let results = self.results.read().await;
        let agg = self.aggregated.read().await;

        let total_jobs = agg.len();
        let total_results: usize = results.values().map(|v| v.len()).sum();
        let total_targets: usize = agg.values().map(|r| r.total_targets).sum();
        let total_open_ports: usize = agg.values().map(|r| r.open_ports_found).sum();

        AggregatorStats {
            total_jobs,
            total_result_entries: total_results,
            total_targets_scanned: total_targets,
            total_open_ports_found: total_open_ports,
        }
    }
}

/// Result summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultSummary {
    pub job_id: String,
    pub total_targets: usize,
    pub total_ports_scanned: usize,
    pub open_ports_found: usize,
    pub scan_duration_ms: u64,
    pub agent_count: usize,
}

impl std::fmt::Display for ResultSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Job {} Summary:", self.job_id)?;
        writeln!(f, "  {} targets, {} ports scanned, {} open ports found", 
            self.total_targets, self.total_ports_scanned, self.open_ports_found)?;
        writeln!(f, "  {} agents, {}ms total", self.agent_count, self.scan_duration_ms)?;
        Ok(())
    }
}

/// Aggregator statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatorStats {
    pub total_jobs: usize,
    pub total_result_entries: usize,
    pub total_targets_scanned: usize,
    pub total_open_ports_found: usize,
}

impl std::fmt::Display for AggregatorStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Aggregator Statistics:")?;
        writeln!(f, "  Jobs: {}", self.total_jobs)?;
        writeln!(f, "  Result Entries: {}", self.total_result_entries)?;
        writeln!(f, "  Targets Scanned: {}", self.total_targets_scanned)?;
        writeln!(f, "  Open Ports Found: {}", self.total_open_ports_found)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::scanner::host_discovery::HostStatus;

    fn create_test_result() -> CompleteScanResult {
        CompleteScanResult {
            target: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            host_status: HostStatus::Up,
            tcp_results: vec![],
            syn_results: vec![],
            udp_results: vec![],
            scan_duration_ms: 1000,
            throttle_stats: None,
        }
    }

    #[tokio::test]
    async fn test_aggregator_creation() {
        let aggregator = ResultAggregator::new(24);
        let stats = aggregator.get_stats().await;
        assert_eq!(stats.total_jobs, 0);
    }

    #[tokio::test]
    async fn test_store_and_retrieve_results() {
        let mut aggregator = ResultAggregator::new(24);
        
        let job_id = "test-job-1".to_string();
        let agent_id = "agent-1".to_string();
        let results = vec![create_test_result()];
        
        let result = aggregator.store_results(job_id.clone(), agent_id, results).await;
        assert!(result.is_ok());
        
        let retrieved = aggregator.get_results(&job_id).await.unwrap();
        assert!(retrieved.is_some());
        
        let agg_results = retrieved.unwrap();
        assert_eq!(agg_results.total_targets, 1);
    }

    #[tokio::test]
    async fn test_list_jobs() {
        let mut aggregator = ResultAggregator::new(24);
        
        aggregator.store_results(
            "job-1".to_string(),
            "agent-1".to_string(),
            vec![create_test_result()],
        ).await.unwrap();
        
        aggregator.store_results(
            "job-2".to_string(),
            "agent-2".to_string(),
            vec![create_test_result()],
        ).await.unwrap();
        
        let jobs = aggregator.list_jobs().await.unwrap();
        assert_eq!(jobs.len(), 2);
    }

    #[tokio::test]
    async fn test_delete_results() {
        let mut aggregator = ResultAggregator::new(24);
        
        let job_id = "test-job".to_string();
        aggregator.store_results(
            job_id.clone(),
            "agent-1".to_string(),
            vec![create_test_result()],
        ).await.unwrap();
        
        let result = aggregator.delete_results(&job_id).await;
        assert!(result.is_ok());
        
        let retrieved = aggregator.get_results(&job_id).await.unwrap();
        assert!(retrieved.is_none());
    }
}

