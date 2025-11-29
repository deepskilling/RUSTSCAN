/// Distributed scanning example
/// 
/// This example demonstrates the distributed scanning capabilities including
/// job scheduling, agent management, and result aggregation.

use nrmap::{ScanScheduler, distributed::{DistributedConfig, DistributedScanner}};
use std::net::{IpAddr, Ipv4Addr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("NrMAP Distributed Scanning Example\n");

    // Example 1: Create a distributed scanner
    println!("Example 1: Distributed Scanner Setup");
    println!("{}", "-".repeat(50));
    
    let config = DistributedConfig {
        enable_distributed: true,
        scheduler_port: 8080,
        agent_port: 8081,
        max_agents: 5,
        job_timeout_seconds: 3600,
        result_retention_hours: 24,
    };
    
    let mut scanner = DistributedScanner::new(config)?;
    println!("Distributed scanner initialized");
    println!("  Max agents: {}", scanner.config().max_agents);
    println!("  Scheduler port: {}", scanner.config().scheduler_port);
    println!();

    // Example 2: Submit a scan job
    println!("Example 2: Submit Scan Job");
    println!("{}", "-".repeat(50));
    
    let targets = vec![
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)),
    ];
    let ports = vec![80, 443, 22, 21];
    
    let job_id = scanner.submit_job(targets.clone(), ports.clone()).await?;
    println!("Job submitted: {}", job_id);
    println!("  Targets: {}", targets.len());
    println!("  Ports: {}", ports.len());
    println!();

    // Example 3: Check job status
    println!("Example 3: Check Job Status");
    println!("{}", "-".repeat(50));
    
    if let Some(status) = scanner.get_job_status(&job_id).await? {
        println!("Job status: {}", status);
    }
    println!();

    // Example 4: Register agents
    println!("Example 4: Register Agents");
    println!("{}", "-".repeat(50));
    
    scanner.register_agent("agent-1".to_string(), "10.0.0.1:8081".to_string()).await?;
    scanner.register_agent("agent-2".to_string(), "10.0.0.2:8081".to_string()).await?;
    println!("Registered 2 agents");
    println!();

    // Example 5: Use standalone scheduler
    println!("Example 5: Standalone Scheduler");
    println!("{}", "-".repeat(50));
    
    let mut scheduler = ScanScheduler::new(10, 7200);
    
    // Submit multiple jobs
    let job1 = scheduler.submit_job(
        vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
        vec![80, 443],
    ).await?;
    
    let job2 = scheduler.submit_job(
        vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
        vec![22, 3389],
    ).await?;
    
    println!("Submitted 2 jobs:");
    println!("  Job 1: {}", job1);
    println!("  Job 2: {}", job2);
    println!();

    // Get scheduler stats
    let stats = scheduler.get_stats().await;
    println!("{}", stats);

    println!("Example completed!");
    println!("\nNote: Full distributed scanning requires network communication");
    println!("between scheduler and agents. This example demonstrates the API.");

    Ok(())
}

