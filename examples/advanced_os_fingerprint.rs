//! Advanced OS Fingerprinting Example
//!
//! This example demonstrates the advanced OS fingerprinting capabilities:
//! - Clock skew analysis
//! - Passive fingerprinting

use nrmap::os_fingerprint::{
    ClockSkewAnalyzer, PassiveAnalyzer, PassiveObservation, OsFingerprintEngine,
};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("=== NrMAP Advanced OS Fingerprinting Demo ===\n");

    // Target configuration
    let target: IpAddr = "192.168.1.100".parse()?;
    let port = 80;

    // ===== Clock Skew Analysis =====
    println!("1. Clock Skew Analysis");
    println!("   Analyzing TCP timestamp behavior to detect OS...\n");

    let clock_skew_analyzer = ClockSkewAnalyzer::new();
    
    match clock_skew_analyzer.analyze(target, port, 20).await {
        Ok(analysis) => {
            println!("   ✓ Clock Skew Analysis Results:");
            println!("     Target: {}", analysis.target);
            println!("     Samples collected: {}", analysis.measurements.len());
            
            if let Some(skew_ppm) = analysis.skew_ppm {
                println!("     Clock skew: {:.2} ppm", skew_ppm);
            }
            
            if let Some(freq_hz) = analysis.clock_frequency_hz {
                println!("     Clock frequency: {:.2} Hz", freq_hz);
            }
            
            if let Some(std_dev) = analysis.skew_std_dev {
                println!("     Standard deviation: {:.2}", std_dev);
            }
            
            println!("     Confidence: {:.2}%", analysis.confidence * 100.0);
            
            if !analysis.os_hints.is_empty() {
                println!("     OS Hints:");
                for hint in &analysis.os_hints {
                    println!("       - {}", hint);
                }
            }
            println!();
        }
        Err(e) => {
            eprintln!("   ✗ Clock skew analysis failed: {}\n", e);
        }
    }

    // ===== Passive Fingerprinting =====
    println!("2. Passive Fingerprinting");
    println!("   Analyzing captured network traffic...\n");

    let mut passive_analyzer = PassiveAnalyzer::new();
    
    // Simulate adding passive observations (in real scenario, from packet capture)
    println!("   Simulating packet capture...");
    for i in 0..15 {
        let observation = PassiveObservation {
            src_ip: target,
            dst_ip: "10.0.0.1".parse()?,
            src_port: 12345 + i,
            dst_port: 80,
            ttl: 64,
            window_size: 65535,
            mss: Some(1460),
            tcp_options: vec![2, 4, 5, 180, 1, 3, 3, 7], // MSS, NOP, Window Scale=7
            tcp_flags: 0x02, // SYN
            timestamp_us: SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_micros() as u64 + (i as u64 * 100000),
            df_flag: true,
        };
        passive_analyzer.add_observation(observation);
    }
    
    println!("   Captured {} packets\n", passive_analyzer.observation_count(target));
    
    // Analyze TTL + MSS profile
    match passive_analyzer.analyze_ttl_mss(target) {
        Ok(profile) => {
            println!("   ✓ TTL + MSS Profile:");
            println!("     Initial TTL: {}", profile.initial_ttl);
            println!("     MSS: {}", profile.mss);
            println!("     Window size: {}", profile.window_size);
            println!("     DF flag set: {}", profile.df_flag_set);
            println!();
        }
        Err(e) => {
            eprintln!("   ✗ TTL+MSS analysis failed: {}\n", e);
        }
    }
    
    // Analyze handshake pattern
    match passive_analyzer.analyze_handshake_pattern(target) {
        Ok(pattern) => {
            println!("   ✓ Handshake Pattern:");
            println!("     SYN window average: {:.0}", pattern.syn_window_avg);
            println!("     SYN-ACK window average: {:.0}", pattern.syn_ack_window_avg);
            println!("     TCP options: {:?}", pattern.common_options);
            if let Some(scale) = pattern.window_scale {
                println!("     Window scale: {}", scale);
            }
            println!();
        }
        Err(e) => {
            eprintln!("   ✗ Handshake pattern analysis failed: {}\n", e);
        }
    }
    
    // Estimate uptime
    match passive_analyzer.estimate_uptime(target) {
        Ok(uptime) => {
            println!("   ✓ Estimated Uptime:");
            let days = uptime.seconds / 86400;
            let hours = (uptime.seconds % 86400) / 3600;
            let minutes = (uptime.seconds % 3600) / 60;
            println!("     {}d {}h {}m", days, hours, minutes);
            println!();
        }
        Err(e) => {
            eprintln!("   ✗ Uptime estimation failed: {}\n", e);
        }
    }
    
    // Complete passive fingerprinting analysis
    match passive_analyzer.analyze(target) {
        Ok(result) => {
            println!("   ✓ Complete Passive Fingerprint:");
            println!("     Packets observed: {}", result.packets_observed);
            println!("     Confidence: {:.2}%", result.confidence * 100.0);
            
            if !result.os_hints.is_empty() {
                println!("     OS Hints:");
                for hint in &result.os_hints {
                    println!("       - {}", hint);
                }
            }
            println!();
        }
        Err(e) => {
            eprintln!("   ✗ Passive analysis failed: {}\n", e);
        }
    }

    // ===== Integrated Fingerprinting =====
    println!("3. Complete OS Fingerprinting (All Techniques)");
    println!("   Combining all fingerprinting methods...\n");

    let engine = OsFingerprintEngine::new();
    
    match engine.fingerprint(target, port).await {
        Ok(fingerprint) => {
            println!("   ✓ Complete Fingerprint Results:");
            println!("     Target: {}", fingerprint.target);
            println!("     Detection time: {}ms", fingerprint.detection_time_ms);
            
            println!("\n   Techniques used:");
            if fingerprint.tcp_fingerprint.is_some() {
                println!("     ✓ TCP/IP Stack Fingerprinting");
            }
            if fingerprint.icmp_fingerprint.is_some() {
                println!("     ✓ ICMP-Based Fingerprinting");
            }
            if fingerprint.udp_fingerprint.is_some() {
                println!("     ✓ UDP-Based Fingerprinting");
            }
            if fingerprint.protocol_hints.is_some() {
                println!("     ✓ Protocol/Service OS Hints");
            }
            if fingerprint.clock_skew.is_some() {
                println!("     ✓ Clock Skew Analysis");
                if let Some(ref clock) = fingerprint.clock_skew {
                    if let Some(skew) = clock.skew_ppm {
                        println!("       Clock skew: {:.2} ppm", skew);
                    }
                }
            }
            if fingerprint.passive_fingerprint.is_some() {
                println!("     ✓ Passive Fingerprinting");
                if let Some(ref passive) = fingerprint.passive_fingerprint {
                    println!("       Packets observed: {}", passive.packets_observed);
                }
            }
            
            // Match against database
            println!("\n   Matching against OS database...");
            match engine.match_os(&fingerprint) {
                Ok(matches) => {
                    if matches.is_empty() {
                        println!("     No confident matches found");
                    } else {
                        println!("     Top matches:");
                        for (i, m) in matches.iter().take(3).enumerate() {
                            println!("     {}. {} - Confidence: {:.2}%", 
                                   i + 1, m.os_name, m.confidence_score * 100.0);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("     ✗ OS matching failed: {}", e);
                }
            }
            println!();
        }
        Err(e) => {
            eprintln!("   ✗ Complete fingerprinting failed: {}\n", e);
        }
    }

    // ===== Comparison: Active vs Passive =====
    println!("4. Comparison: Active vs Passive Fingerprinting");
    println!("   ┌─────────────────────┬──────────┬────────────┐");
    println!("   │ Technique           │ Stealth  │ Accuracy   │");
    println!("   ├─────────────────────┼──────────┼────────────┤");
    println!("   │ TCP/IP Stack        │ Low      │ High       │");
    println!("   │ ICMP-Based          │ Medium   │ High       │");
    println!("   │ UDP-Based           │ Medium   │ Medium     │");
    println!("   │ Protocol Hints      │ Low      │ Medium     │");
    println!("   │ Clock Skew          │ Low      │ High       │");
    println!("   │ Passive             │ Very High│ Medium     │");
    println!("   └─────────────────────┴──────────┴────────────┘");
    println!();

    println!("=== Demo Complete ===");
    
    Ok(())
}

