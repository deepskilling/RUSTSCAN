/// Detection engine example
/// 
/// This example demonstrates using the detection engine for banner grabbing,
/// service fingerprinting, and OS detection.

use nrmap::{DetectionEngine, detection::DetectionEngineConfig};
use std::net::IpAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("NrMAP Detection Engine Example\n");

    // Create detection engine with default config
    let config = DetectionEngineConfig::default();
    let engine = DetectionEngine::new(config)?;
    println!("Detection engine initialized\n");

    // Example 1: Grab banner from localhost HTTP
    println!("Example 1: Banner Grabbing");
    println!("{}",  "-".repeat(50));
    
    let target: IpAddr = "127.0.0.1".parse()?;
    let port = 80;
    
    match engine.grab_banner(target, port).await? {
        Some(banner) => {
            println!("Banner grabbed from {}:{}", target, port);
            println!("Data: {}", banner.data.chars().take(100).collect::<String>());
            println!("Response time: {}ms", banner.response_time_ms);
        }
        None => {
            println!("No banner received from {}:{}", target, port);
        }
    }
    
    println!();

    // Example 2: Service Detection
    println!("Example 2: Service Detection");
    println!("{}", "-".repeat(50));
    
    let test_banner = Some("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1");
    match engine.detect_service(target, 22, test_banner).await? {
        Some(service) => {
            println!("Service detected:");
            println!("  Name: {}", service.service_name);
            if let Some(product) = service.product {
                println!("  Product: {}", product);
            }
            if let Some(version) = service.version {
                println!("  Version: {}", version);
            }
            println!("  Confidence: {:.0}%", service.confidence * 100.0);
        }
        None => {
            println!("No service match found");
        }
    }
    
    println!();

    // Example 3: OS Detection
    println!("Example 3: OS Detection");
    println!("{}", "-".repeat(50));
    
    let os_matches = engine.detect_os(target).await?;
    if os_matches.is_empty() {
        println!("OS detection requires active probing (framework mode)");
    } else {
        println!("Detected {} possible OS matches:", os_matches.len());
        for (i, os_match) in os_matches.iter().enumerate() {
            println!("  {}. {}", i + 1, os_match);
        }
    }
    
    println!();

    // Example 4: Comprehensive Detection
    println!("Example 4: Comprehensive Detection");
    println!("{}", "-".repeat(50));
    
    println!("Running comprehensive detection on {}:80...", target);
    match engine.detect_all(target, 80).await {
        Ok(result) => {
            println!("{}", result);
        }
        Err(e) => {
            println!("Detection failed: {}", e);
        }
    }

    println!("\nExample completed!");

    Ok(())
}

