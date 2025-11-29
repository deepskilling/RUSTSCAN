/// Scan job scheduler for distributed scanning
/// 
/// This module implements job scheduling, work distribution, and agent management
/// for distributed scanning operations.

use crate::error::{ScanError, ScanResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Scan job information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub job_id: String,
    pub targets: Vec<IpAddr>,
    pub ports: Vec<u16>,
    pub status: JobStatus,
    pub assigned_agent: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Job status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStatus {
    Pending,
    Assigned,
    Running,
    Completed,
    Failed,
    Timeout,
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JobStatus::Pending => write!(f, "Pending"),
            JobStatus::Assigned => write!(f, "Assigned"),
            JobStatus::Running => write!(f, "Running"),
            JobStatus::Completed => write!(f, "Completed"),
            JobStatus::Failed => write!(f, "Failed"),
            JobStatus::Timeout => write!(f, "Timeout"),
        }
    }
}

/// Registered agent information
#[derive(Debug, Clone)]
struct AgentInfo {
    #[allow(dead_code)]
    agent_id: String,
    #[allow(dead_code)]
    address: String,
    status: AgentHealthStatus,
    current_job: Option<String>,
    last_heartbeat: chrono::DateTime<chrono::Utc>,
    jobs_completed: usize,
}

/// Agent health status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum AgentHealthStatus {
    Healthy,
    Busy,
    Unhealthy,
    Offline,
}

/// Scan scheduler
pub struct ScanScheduler {
    jobs: Arc<RwLock<HashMap<String, ScanJob>>>,
    agents: Arc<RwLock<HashMap<String, AgentInfo>>>,
    max_agents: usize,
    job_timeout_seconds: u64,
}

impl ScanScheduler {
    /// Create a new scan scheduler
    /// 
    /// # Arguments
    /// * `max_agents` - Maximum number of agents to manage
    /// * `job_timeout_seconds` - Job timeout in seconds
    pub fn new(max_agents: usize, job_timeout_seconds: u64) -> Self {
        info!(
            "Initializing scan scheduler: max_agents={}, timeout={}s",
            max_agents, job_timeout_seconds
        );
        
        Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
            agents: Arc::new(RwLock::new(HashMap::new())),
            max_agents,
            job_timeout_seconds,
        }
    }

    /// Get job timeout in seconds
    pub fn job_timeout(&self) -> u64 {
        self.job_timeout_seconds
    }

    /// Submit a new scan job
    /// 
    /// # Arguments
    /// * `targets` - Target IP addresses to scan
    /// * `ports` - Ports to scan on each target
    /// 
    /// # Returns
    /// * `ScanResult<String>` - Job ID
    pub async fn submit_job(
        &mut self,
        targets: Vec<IpAddr>,
        ports: Vec<u16>,
    ) -> ScanResult<String> {
        if targets.is_empty() {
            return Err(ScanError::validation_error("targets", "No targets provided"));
        }

        if ports.is_empty() {
            return Err(ScanError::validation_error("ports", "No ports provided"));
        }

        // Generate unique job ID
        let job_id = format!("job_{}", uuid::Uuid::new_v4());
        
        let job = ScanJob {
            job_id: job_id.clone(),
            targets,
            ports,
            status: JobStatus::Pending,
            assigned_agent: None,
            created_at: chrono::Utc::now(),
            started_at: None,
            completed_at: None,
        };

        let mut jobs = self.jobs.write().await;
        jobs.insert(job_id.clone(), job.clone());
        drop(jobs);

        info!(
            "Job {} submitted: {} targets, {} ports",
            job_id,
            job.targets.len(),
            job.ports.len()
        );

        // Try to assign to an available agent
        self.try_assign_job(&job_id).await?;

        Ok(job_id)
    }

    /// Try to assign a job to an available agent
    async fn try_assign_job(&self, job_id: &str) -> ScanResult<()> {
        let agents = self.agents.read().await;
        
        // Find an available agent
        let available_agent = agents
            .iter()
            .find(|(_, agent)| {
                agent.status == AgentHealthStatus::Healthy && agent.current_job.is_none()
            })
            .map(|(id, _)| id.clone());

        drop(agents);

        if let Some(agent_id) = available_agent {
            let mut jobs = self.jobs.write().await;
            
            if let Some(job) = jobs.get_mut(job_id) {
                job.status = JobStatus::Assigned;
                job.assigned_agent = Some(agent_id.clone());
                
                info!("Job {} assigned to agent {}", job_id, agent_id);
                
                // Update agent status
                let mut agents = self.agents.write().await;
                if let Some(agent) = agents.get_mut(&agent_id) {
                    agent.status = AgentHealthStatus::Busy;
                    agent.current_job = Some(job_id.to_string());
                }
            }
        } else {
            debug!("No available agents for job {}", job_id);
        }

        Ok(())
    }

    /// Get job status
    pub async fn get_job_status(&self, job_id: &str) -> ScanResult<Option<JobStatus>> {
        let jobs = self.jobs.read().await;
        Ok(jobs.get(job_id).map(|job| job.status))
    }

    /// Get job details
    pub async fn get_job(&self, job_id: &str) -> ScanResult<Option<ScanJob>> {
        let jobs = self.jobs.read().await;
        Ok(jobs.get(job_id).cloned())
    }

    /// Register a new agent
    /// 
    /// # Arguments
    /// * `agent_id` - Unique agent identifier
    /// * `address` - Agent network address
    pub async fn register_agent(&mut self, agent_id: String, address: String) -> ScanResult<()> {
        let mut agents = self.agents.write().await;

        if agents.len() >= self.max_agents {
            return Err(ScanError::scanner_error(
                "Maximum number of agents reached"
            ));
        }

        if agents.contains_key(&agent_id) {
            return Err(ScanError::validation_error(
                "agent_id",
                "Agent already registered",
            ));
        }

        let agent = AgentInfo {
            agent_id: agent_id.clone(),
            address: address.clone(),
            status: AgentHealthStatus::Healthy,
            current_job: None,
            last_heartbeat: chrono::Utc::now(),
            jobs_completed: 0,
        };

        agents.insert(agent_id.clone(), agent);
        info!("Agent {} registered at {}", agent_id, address);

        Ok(())
    }

    /// Unregister an agent
    pub async fn unregister_agent(&mut self, agent_id: &str) -> ScanResult<()> {
        let mut agents = self.agents.write().await;
        
        if let Some(agent) = agents.remove(agent_id) {
            info!("Agent {} unregistered", agent_id);
            
            // If agent had a job, mark it as failed
            if let Some(job_id) = agent.current_job {
                drop(agents);
                self.mark_job_failed(&job_id, "Agent disconnected").await?;
            }
        } else {
            warn!("Attempted to unregister unknown agent: {}", agent_id);
        }

        Ok(())
    }

    /// Update agent heartbeat
    pub async fn agent_heartbeat(&mut self, agent_id: &str) -> ScanResult<()> {
        let mut agents = self.agents.write().await;
        
        if let Some(agent) = agents.get_mut(agent_id) {
            agent.last_heartbeat = chrono::Utc::now();
            debug!("Heartbeat received from agent {}", agent_id);
        } else {
            return Err(ScanError::validation_error(
                "agent_id",
                "Agent not registered",
            ));
        }

        Ok(())
    }

    /// Mark job as running
    pub async fn mark_job_running(&mut self, job_id: &str) -> ScanResult<()> {
        let mut jobs = self.jobs.write().await;
        
        if let Some(job) = jobs.get_mut(job_id) {
            job.status = JobStatus::Running;
            job.started_at = Some(chrono::Utc::now());
            info!("Job {} started", job_id);
        }

        Ok(())
    }

    /// Mark job as completed
    pub async fn mark_job_completed(&mut self, job_id: &str) -> ScanResult<()> {
        let agent_id_opt = {
            let mut jobs = self.jobs.write().await;
            
            if let Some(job) = jobs.get_mut(job_id) {
                job.status = JobStatus::Completed;
                job.completed_at = Some(chrono::Utc::now());
                job.assigned_agent.clone()
            } else {
                None
            }
        };
        
        // Free up the agent
        if let Some(agent_id) = agent_id_opt {
            let mut agents = self.agents.write().await;
            if let Some(agent) = agents.get_mut(&agent_id) {
                agent.status = AgentHealthStatus::Healthy;
                agent.current_job = None;
                agent.jobs_completed += 1;
            }
            
            info!("Job {} completed", job_id);
        }

        Ok(())
    }

    /// Mark job as failed
    pub async fn mark_job_failed(&mut self, job_id: &str, _reason: &str) -> ScanResult<()> {
        let agent_id_opt = {
            let mut jobs = self.jobs.write().await;
            
            if let Some(job) = jobs.get_mut(job_id) {
                job.status = JobStatus::Failed;
                job.completed_at = Some(chrono::Utc::now());
                job.assigned_agent.clone()
            } else {
                None
            }
        };
        
        // Free up the agent
        if let Some(agent_id) = agent_id_opt {
            let mut agents = self.agents.write().await;
            if let Some(agent) = agents.get_mut(&agent_id) {
                agent.status = AgentHealthStatus::Healthy;
                agent.current_job = None;
            }
            
            warn!("Job {} failed", job_id);
        }

        Ok(())
    }

    /// Get list of all jobs
    pub async fn list_jobs(&self) -> ScanResult<Vec<ScanJob>> {
        let jobs = self.jobs.read().await;
        Ok(jobs.values().cloned().collect())
    }

    /// Get list of all agents
    pub async fn list_agents(&self) -> ScanResult<Vec<String>> {
        let agents = self.agents.read().await;
        Ok(agents.keys().cloned().collect())
    }

    /// Get scheduler statistics
    pub async fn get_stats(&self) -> SchedulerStats {
        let jobs = self.jobs.read().await;
        let agents = self.agents.read().await;

        let total_jobs = jobs.len();
        let pending = jobs.values().filter(|j| j.status == JobStatus::Pending).count();
        let running = jobs.values().filter(|j| j.status == JobStatus::Running).count();
        let completed = jobs.values().filter(|j| j.status == JobStatus::Completed).count();
        let failed = jobs.values().filter(|j| j.status == JobStatus::Failed).count();

        SchedulerStats {
            total_jobs,
            pending_jobs: pending,
            running_jobs: running,
            completed_jobs: completed,
            failed_jobs: failed,
            total_agents: agents.len(),
            healthy_agents: agents.values().filter(|a| a.status == AgentHealthStatus::Healthy).count(),
            busy_agents: agents.values().filter(|a| a.status == AgentHealthStatus::Busy).count(),
        }
    }
}

/// Scheduler statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerStats {
    pub total_jobs: usize,
    pub pending_jobs: usize,
    pub running_jobs: usize,
    pub completed_jobs: usize,
    pub failed_jobs: usize,
    pub total_agents: usize,
    pub healthy_agents: usize,
    pub busy_agents: usize,
}

impl std::fmt::Display for SchedulerStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Scheduler Statistics:")?;
        writeln!(f, "  Jobs: {} total ({} pending, {} running, {} completed, {} failed)", 
            self.total_jobs, self.pending_jobs, self.running_jobs, 
            self.completed_jobs, self.failed_jobs)?;
        writeln!(f, "  Agents: {} total ({} healthy, {} busy)", 
            self.total_agents, self.healthy_agents, self.busy_agents)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_scheduler_creation() {
        let scheduler = ScanScheduler::new(10, 3600);
        let stats = scheduler.get_stats().await;
        assert_eq!(stats.total_jobs, 0);
        assert_eq!(stats.total_agents, 0);
    }

    #[tokio::test]
    async fn test_submit_job() {
        let mut scheduler = ScanScheduler::new(10, 3600);
        
        let targets = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let ports = vec![80, 443];
        
        let result = scheduler.submit_job(targets, ports).await;
        assert!(result.is_ok());
        
        let job_id = result.unwrap();
        let job = scheduler.get_job(&job_id).await.unwrap();
        assert!(job.is_some());
    }

    #[tokio::test]
    async fn test_register_agent() {
        let mut scheduler = ScanScheduler::new(10, 3600);
        
        let result = scheduler.register_agent(
            "agent-1".to_string(),
            "127.0.0.1:8081".to_string()
        ).await;
        
        assert!(result.is_ok());
        
        let agents = scheduler.list_agents().await.unwrap();
        assert_eq!(agents.len(), 1);
    }

    #[tokio::test]
    async fn test_job_status_transitions() {
        let mut scheduler = ScanScheduler::new(10, 3600);
        
        let targets = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let ports = vec![80];
        
        let job_id = scheduler.submit_job(targets, ports).await.unwrap();
        
        // Mark as running
        scheduler.mark_job_running(&job_id).await.unwrap();
        let status = scheduler.get_job_status(&job_id).await.unwrap();
        assert_eq!(status, Some(JobStatus::Running));
        
        // Mark as completed
        scheduler.mark_job_completed(&job_id).await.unwrap();
        let status = scheduler.get_job_status(&job_id).await.unwrap();
        assert_eq!(status, Some(JobStatus::Completed));
    }
}

