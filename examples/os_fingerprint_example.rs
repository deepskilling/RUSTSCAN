/// OS Fingerprinting Example
/// 
/// This example demonstrates comprehensive OS detection through TCP/IP and ICMP
/// fingerprinting techniques.

use nrmap::os_fingerprint::{OsFingerprintEngine, OsFingerprintConfig};
use std::net::{IpAddr, Ipv4Addr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("NrMAP OS Fingerprinting Example\n");

    // Example 1: Create OS fingerprinting engine
    println!("Example 1: OS Fingerprinting Engine");
    println!("{}", "-".repeat(70));
    
    let engine = OsFingerprintEngine::new();
    let db = engine.database();
    println!("Fingerprint engine initialized");
    println!("  Database loaded: {} OS signatures", db.signature_count());
    println!();

    // Example 2: View database signatures
    println!("Example 2: OS Signatures in Database");
    println!("{}", "-".repeat(70));
    
    for (os_name, signature) in db.signatures().iter().take(5) {
        println!("  • {} ({})", os_name, signature.os_family);
        if let Some(ref version) = signature.os_version {
            println!("    Version: {}", version);
        }
        if let Some(ref tcp_sig) = signature.tcp_signature {
            println!("    TCP TTL: {}-{}", tcp_sig.ttl_range.0, tcp_sig.ttl_range.1);
            println!("    Window: {}-{}", tcp_sig.window_size_range.0, tcp_sig.window_size_range.1);
        }
        println!();
    }

    // Example 3: Perform fingerprinting (framework mode)
    println!("Example 3: Fingerprint Collection");
    println!("{}", "-".repeat(70));
    
    let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let port = 80;
    
    println!("Target: {}:{}", target, port);
    println!("Collecting fingerprints...");
    
    // This uses framework implementations
    let fingerprint = engine.fingerprint(target, port).await?;
    
    println!("  Detection time: {} ms", fingerprint.detection_time_ms);
    
    if let Some(ref tcp_fp) = fingerprint.tcp_fingerprint {
        println!("\n  TCP Fingerprint:");
        println!("    Initial TTL: {}", tcp_fp.initial_ttl);
        println!("    Window Size: {}", tcp_fp.window_size);
        println!("    MSS: {:?}", tcp_fp.mss);
        println!("    DF Flag: {}", tcp_fp.df_flag);
        println!("    IP ID Pattern: {:?}", tcp_fp.ip_id_pattern);
        println!("    RST Behavior: {:?}", tcp_fp.rst_behavior);
        println!("    ECN Support: {}", tcp_fp.ecn_support);
        println!("    TCP Options: {} options", tcp_fp.tcp_options.len());
    }
    
    if let Some(ref icmp_fp) = fingerprint.icmp_fingerprint {
        println!("\n  ICMP Fingerprint:");
        if let Some(ref echo) = icmp_fp.echo_reply {
            println!("    Echo TTL: {}", echo.ttl);
            println!("    Payload Echo: {}", echo.payload_echo);
        }
        println!("    Timestamp: {:?}", icmp_fp.timestamp_behavior);
        println!("    Rate Limiting: {}", icmp_fp.rate_limiting.has_rate_limiting);
    }
    
    if let Some(ref udp_fp) = fingerprint.udp_fingerprint {
        println!("\n  UDP Fingerprint:");
        println!("    Sends Unreachable: {}", udp_fp.port_unreachable_behavior.sends_icmp_unreachable);
        println!("    Response Pattern: {}", udp_fp.response_pattern);
        println!("    Payload Echoing: {} bytes", udp_fp.payload_echoing.bytes_echoed);
    }
    
    if let Some(ref proto_hints) = fingerprint.protocol_hints {
        println!("\n  Protocol Hints:");
        if let Some(ref ssh) = proto_hints.ssh_hints {
            println!("    SSH: {} ({})", ssh.software, ssh.banner);
        }
        if let Some(ref smb) = proto_hints.smb_hints {
            if let Some(ref os) = smb.os_version {
                println!("    SMB OS: {}", os);
            }
        }
        if let Some(ref http) = proto_hints.http_hints {
            if let Some(ref server) = http.server_header {
                println!("    HTTP Server: {}", server);
            }
        }
        if let Some(ref tls) = proto_hints.tls_hints {
            println!("    TLS: {}", tls.tls_version);
        }
    }
    println!();

    // Example 4: Match against database
    println!("Example 4: OS Detection Matching");
    println!("{}", "-".repeat(70));
    
    let matches = engine.match_os(&fingerprint)?;
    
    if matches.is_empty() {
        println!("No OS matches found");
    } else {
        println!("Found {} potential OS matches:\n", matches.len());
        
        for (i, os_match) in matches.iter().enumerate() {
            println!("{}. {}", i + 1, os_match.os_name);
            if let Some(ref version) = os_match.os_version {
                println!("   Version: {}", version);
            }
            println!("   Family: {}", os_match.os_family);
            println!("   Confidence: {} ({:.1}%)", 
                os_match.confidence, 
                os_match.confidence_score * 100.0
            );
            
            if !os_match.matching_features.is_empty() {
                println!("   Matching Features:");
                for feature in &os_match.matching_features {
                    println!("     - {}", feature);
                }
            }
            println!();
        }
    }

    // Example 5: Configuration
    println!("Example 5: Fingerprinting Configuration");
    println!("{}", "-".repeat(70));
    
    let config = OsFingerprintConfig::default();
    println!("Default Configuration:");
    println!("  TCP Fingerprinting: {}", config.enable_tcp_fingerprinting);
    println!("  ICMP Fingerprinting: {}", config.enable_icmp_fingerprinting);
    println!("  TCP Timeout: {} ms", config.tcp_timeout_ms);
    println!("  ICMP Timeout: {} ms", config.icmp_timeout_ms);
    println!("  Max Retries: {}", config.max_retries);
    println!("  Confidence Threshold: {:.2}", config.confidence_threshold);
    println!();

    // Example 6: Analyze OS hints from characteristics
    println!("Example 6: OS Hints from Characteristics");
    println!("{}", "-".repeat(70));
    
    use nrmap::os_fingerprint::tcp_fingerprint::{ttl_to_os_hint, window_size_to_os_hint};
    
    println!("TTL 64 suggests: {:?}", ttl_to_os_hint(64));
    println!("TTL 128 suggests: {:?}", ttl_to_os_hint(128));
    println!("TTL 255 suggests: {:?}", ttl_to_os_hint(255));
    println!();
    
    println!("Window 29200 suggests: {:?}", window_size_to_os_hint(29200));
    println!("Window 65535 suggests: {:?}", window_size_to_os_hint(65535));
    println!("Window 8192 suggests: {:?}", window_size_to_os_hint(8192));
    println!();

    println!("Example completed!");
    println!("\nNote: This example uses framework implementations.");
    println!("In production, actual network probes would be sent to collect real data.");
    println!("\nOS Fingerprinting Features:");
    println!("  ✓ TCP/IP Stack Analysis (TTL, Window, MSS, Options, DF, IP ID)");
    println!("  ✓ SYN/ACK Response Patterns");
    println!("  ✓ RST Packet Behavior");
    println!("  ✓ ECN/CWR Analysis");
    println!("  ✓ ICMP Echo Reply Structure");
    println!("  ✓ ICMP Unreachable Codes");
    println!("  ✓ ICMP Timestamp Behavior");
    println!("  ✓ ICMP Rate-Limiting Fingerprints");
    println!("  ✓ UDP Fingerprinting (Port Unreachable, Payload Echoing, Response Patterns)");
    println!("  ✓ SSH Banner Fingerprinting");
    println!("  ✓ SMB OS Detection");
    println!("  ✓ HTTP Header Analysis");
    println!("  ✓ TLS Fingerprint Extraction");
    println!("  ✓ Comprehensive OS Database (6+ signatures)");
    println!("  ✓ Advanced Matching Engine with Confidence Scoring");

    Ok(())
}

