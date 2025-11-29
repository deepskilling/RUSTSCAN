//! Active Probe Library Example
//!
//! Demonstrates the Nmap-style active probe library for OS fingerprinting:
//! - TCP T1-T7 probes
//! - UDP U1 probe
//! - ICMP IE probe
//! - SEQ probes for ISN analysis
//! - ECN probe

use nrmap::os_fingerprint::{ActiveProbeLibrary, TcpProbeType, SeqPredictability, OsFingerprintEngine};
use std::net::IpAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("=== NrMAP Active Probe Library Demo ===\n");

    let target: IpAddr = "192.168.1.100".parse()?;
    let open_port = 80;
    let closed_port = 81;

    println!("Target: {}", target);
    println!("Open port: {}", open_port);
    println!("Closed port: {}\n", closed_port);

    // ===== TCP T1-T7 Probes =====
    println!("1. TCP Probe Set (T1-T7)");
    println!("   These probes send various TCP packets with different flags and options\n");

    let library = ActiveProbeLibrary::new(3000);

    // Run all probes
    match library.probe_all(target, open_port, closed_port).await {
        Ok(results) => {
            println!("   ✓ Active Probe Results:");
            println!("     Total time: {}ms\n", results.total_time_ms);

            // TCP Probes
            println!("   TCP Probes (T1-T7):");
            for probe in &results.tcp_probes {
                print!("     {:?}: ", probe.probe_type);
                if probe.responded {
                    println!("Response received");
                    if let Some(flags) = probe.flags {
                        print!("       Flags: ");
                        if flags & 0x02 != 0 { print!("SYN "); }
                        if flags & 0x10 != 0 { print!("ACK "); }
                        if flags & 0x04 != 0 { print!("RST "); }
                        if flags & 0x01 != 0 { print!("FIN "); }
                        println!();
                    }
                    if let Some(win) = probe.window_size {
                        println!("       Window: {}", win);
                    }
                    if let Some(ttl) = probe.ttl {
                        println!("       TTL: {}", ttl);
                    }
                    if let Some(ip_id) = probe.ip_id {
                        println!("       IP ID: 0x{:04x}", ip_id);
                    }
                    println!("       DF flag: {}", probe.df_flag);
                    println!("       Response time: {}μs", probe.response_time_us);
                } else {
                    println!("No response");
                }
            }
            println!();

            // UDP Probe
            if let Some(ref udp) = results.udp_probe {
                println!("   UDP U1 Probe:");
                println!("     ICMP Unreachable: {}", udp.icmp_unreachable);
                if let Some(icmp_type) = udp.icmp_type {
                    println!("     ICMP Type: {}", icmp_type);
                }
                if let Some(icmp_code) = udp.icmp_code {
                    println!("     ICMP Code: {}", icmp_code);
                }
                if let Some(ttl) = udp.ttl {
                    println!("     TTL: {}", ttl);
                }
                println!("     Response time: {}μs", udp.response_time_us);
                println!();
            }

            // ICMP Probe
            if let Some(ref icmp) = results.icmp_probe {
                println!("   ICMP IE Probe:");
                println!("     Echo reply: {}", icmp.echo_reply);
                if let Some(ttl) = icmp.ttl {
                    println!("     TTL: {}", ttl);
                }
                if let Some(ip_id) = icmp.ip_id {
                    println!("     IP ID: 0x{:04x}", ip_id);
                }
                println!("     DF flag: {}", icmp.df_flag);
                println!("     Response time: {}μs", icmp.response_time_us);
                println!();
            }

            // SEQ Probes
            println!("   SEQ Probes (ISN Analysis):");
            println!("     Collected {} sequence samples", results.seq_probes.len());
            
            // Analyze ISN predictability
            let seq_analysis = library.analyze_seq_responses(&results.seq_probes);
            if let Some(gcd) = seq_analysis.gcd {
                println!("     GCD of ISN differences: {}", gcd);
            }
            if let Some(avg) = seq_analysis.avg_rate {
                println!("     Average ISN increment: {:.2}", avg);
            }
            if let Some(std_dev) = seq_analysis.std_dev {
                println!("     Standard deviation: {:.2}", std_dev);
            }
            
            print!("     Predictability: ");
            match seq_analysis.predictability {
                SeqPredictability::Constant => println!("Constant (weak security)"),
                SeqPredictability::Incremental => println!("Incremental (weak security)"),
                SeqPredictability::TimeDependent => println!("Time-dependent (moderate security)"),
                SeqPredictability::Random => println!("Random (strong security)"),
                SeqPredictability::Unknown => println!("Unknown (insufficient data)"),
            }
            
            println!("\n     ISN values:");
            for (i, seq_probe) in results.seq_probes.iter().enumerate() {
                println!("       Probe {}: ISN=0x{:08x}, IP_ID=0x{:04x}", 
                         i + 1, 
                         seq_probe.isn, 
                         seq_probe.ip_id.unwrap_or(0));
            }
            println!();

            // ECN Probe
            if let Some(ref ecn) = results.ecn_probe {
                println!("   ECN Probe:");
                println!("     ECN supported: {}", ecn.ecn_supported);
                println!("     CWR flag: {}", ecn.cwr_flag);
                println!("     ECE flag: {}", ecn.ece_flag);
                println!();
            }
        }
        Err(e) => {
            eprintln!("   ✗ Probe failed: {}\n", e);
        }
    }

    // ===== Integrated OS Fingerprinting =====
    println!("2. Integrated OS Fingerprinting with Active Probes");
    println!("   Using active probes as part of comprehensive fingerprinting\n");

    let engine = OsFingerprintEngine::new();
    
    // Use active probes (set to true for maximum detection)
    match engine.fingerprint(target, open_port, Some(closed_port), true).await {
        Ok(fingerprint) => {
            println!("   ✓ Complete Fingerprint:");
            println!("     Detection time: {}ms", fingerprint.detection_time_ms);
            
            if let Some(ref active) = fingerprint.active_probes {
                println!("\n     Active Probes:");
                println!("       TCP probes: {}", active.tcp_probes.len());
                println!("       UDP probe: {}", if active.udp_probe.is_some() { "✓" } else { "✗" });
                println!("       ICMP probe: {}", if active.icmp_probe.is_some() { "✓" } else { "✗" });
                println!("       SEQ probes: {}", active.seq_probes.len());
                println!("       ECN probe: {}", if active.ecn_probe.is_some() { "✓" } else { "✗" });
            }
            
            // Match against OS database
            println!("\n     Matching against OS database...");
            match engine.match_os(&fingerprint) {
                Ok(matches) => {
                    if matches.is_empty() {
                        println!("       No confident matches found");
                    } else {
                        println!("       Top matches:");
                        for (i, m) in matches.iter().take(3).enumerate() {
                            println!("       {}. {} - Confidence: {:.2}%", 
                                   i + 1, m.os_name, m.confidence_score * 100.0);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("       ✗ OS matching failed: {}", e);
                }
            }
            println!();
        }
        Err(e) => {
            eprintln!("   ✗ Fingerprinting failed: {}\n", e);
        }
    }

    // ===== Probe Description Table =====
    println!("3. Active Probe Reference");
    println!("   ┌──────┬──────────────────┬────────────────────────────────────┐");
    println!("   │ Probe│ Target Port      │ Description                        │");
    println!("   ├──────┼──────────────────┼────────────────────────────────────┤");
    println!("   │ T1   │ Open             │ SYN with window scale, MSS, etc.   │");
    println!("   │ T2   │ Open             │ No flags, various options          │");
    println!("   │ T3   │ Open             │ SYN with specific options          │");
    println!("   │ T4   │ Open             │ ACK to open port                   │");
    println!("   │ T5   │ Closed           │ SYN to closed port                 │");
    println!("   │ T6   │ Closed           │ ACK to closed port                 │");
    println!("   │ T7   │ Closed           │ FIN/PSH/URG to closed port         │");
    println!("   │ U1   │ Closed           │ UDP to closed port (ICMP unreach)  │");
    println!("   │ IE   │ N/A              │ ICMP Echo Request                  │");
    println!("   │ SEQ  │ Open (×6)        │ TCP SYN for ISN analysis           │");
    println!("   │ ECN  │ Open             │ TCP SYN with ECE+CWR flags         │");
    println!("   └──────┴──────────────────┴────────────────────────────────────┘");
    println!();

    // ===== OS Detection Hints =====
    println!("4. OS Detection Hints from Probe Responses");
    println!("   Different OSes respond differently to these probes:");
    println!();
    println!("   Linux:");
    println!("     - T1: Usually responds with SYN-ACK");
    println!("     - T2: Sends RST");
    println!("     - ISN: Often random (strong security)");
    println!("     - ECN: Usually supported");
    println!();
    println!("   Windows:");
    println!("     - T1: Responds with SYN-ACK, specific window size");
    println!("     - T2: Sends RST with specific characteristics");
    println!("     - ISN: Time-dependent");
    println!("     - ECN: Varies by version");
    println!();
    println!("   BSD/macOS:");
    println!("     - T1: Responds with SYN-ACK");
    println!("     - T2: May not respond or sends RST");
    println!("     - ISN: Random (strong security)");
    println!("     - ECN: Often supported");
    println!();

    println!("=== Demo Complete ===");
    println!("\nNote: This demo simulates probe responses.");
    println!("In production, probes would use raw sockets and analyze real network packets.");
    
    Ok(())
}

