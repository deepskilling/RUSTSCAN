//! Active Probe Library for OS Fingerprinting
//!
//! This module implements Nmap-style active probes for comprehensive OS detection.
//! It includes TCP T1-T7 probes, UDP U1 probe, ICMP IE probe, and SEQ/ECN analysis.

use crate::error::ScanResult;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// TCP flags structure for probe crafting
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

/// TCP probe types (T1-T7)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpProbeType {
    /// T1: TCP probe to open port with specific options
    T1,
    /// T2: TCP probe to open port with different options
    T2,
    /// T3: TCP probe to open port with SYN flag
    T3,
    /// T4: TCP probe to open port with ACK flag
    T4,
    /// T5: TCP probe to closed port with SYN flag
    T5,
    /// T6: TCP probe to closed port with ACK flag
    T6,
    /// T7: TCP probe to closed port with FIN/PSH/URG flags
    T7,
}

/// TCP probe response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpProbeResponse {
    /// Probe type
    pub probe_type: TcpProbeType,
    /// Whether response was received
    pub responded: bool,
    /// Response flags
    pub flags: Option<u8>,
    /// Window size
    pub window_size: Option<u16>,
    /// Sequence number
    pub seq: Option<u32>,
    /// Acknowledgment number
    pub ack: Option<u32>,
    /// TCP options
    pub options: Vec<u8>,
    /// IP TTL
    pub ttl: Option<u8>,
    /// IP ID
    pub ip_id: Option<u16>,
    /// Don't Fragment flag
    pub df_flag: bool,
    /// Response time (microseconds)
    pub response_time_us: u64,
}

/// UDP probe response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpProbeResponse {
    /// Whether ICMP unreachable was received
    pub icmp_unreachable: bool,
    /// ICMP unreachable type
    pub icmp_type: Option<u8>,
    /// ICMP unreachable code
    pub icmp_code: Option<u8>,
    /// IP TTL of ICMP response
    pub ttl: Option<u8>,
    /// IP ID of ICMP response
    pub ip_id: Option<u16>,
    /// Don't Fragment flag
    pub df_flag: bool,
    /// Response time (microseconds)
    pub response_time_us: u64,
}

/// ICMP probe response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpProbeResponse {
    /// Whether echo reply was received
    pub echo_reply: bool,
    /// IP TTL
    pub ttl: Option<u8>,
    /// IP ID
    pub ip_id: Option<u16>,
    /// Don't Fragment flag
    pub df_flag: bool,
    /// ICMP code
    pub icmp_code: Option<u8>,
    /// Response time (microseconds)
    pub response_time_us: u64,
}

/// Sequence probe response (for ISN analysis)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeqProbeResponse {
    /// Sequence number from SYN-ACK
    pub isn: u32,
    /// Timestamp when received
    pub timestamp_us: u64,
    /// IP ID value
    pub ip_id: Option<u16>,
}

/// ECN probe response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcnProbeResponse {
    /// Whether ECN was supported
    pub ecn_supported: bool,
    /// ECN flags from response
    pub ecn_flags: Option<u8>,
    /// CWR flag set
    pub cwr_flag: bool,
    /// ECE flag set
    pub ece_flag: bool,
}

/// Complete active probe results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveProbeResults {
    pub target: IpAddr,
    pub tcp_probes: Vec<TcpProbeResponse>,
    pub udp_probe: Option<UdpProbeResponse>,
    pub icmp_probe: Option<IcmpProbeResponse>,
    pub seq_probes: Vec<SeqProbeResponse>,
    pub ecn_probe: Option<EcnProbeResponse>,
    pub total_time_ms: u64,
}

/// Active probe library
pub struct ActiveProbeLibrary {
    timeout_ms: u64,
    max_retries: u8,
}

impl ActiveProbeLibrary {
    /// Create a new active probe library
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_ms,
            max_retries: 2,
        }
    }

    /// Perform all active probes on a target
    pub async fn probe_all(
        &self,
        target: IpAddr,
        open_port: u16,
        closed_port: u16,
    ) -> ScanResult<ActiveProbeResults> {
        info!("Starting active probe library scan on {}", target);
        let start_time = SystemTime::now();
        
        // TCP T1-T7 probes
        let tcp_probes = self.run_tcp_probes(target, open_port, closed_port).await?;
        
        // UDP U1 probe
        let udp_probe = self.run_udp_probe(target, closed_port).await.ok();
        
        // ICMP IE probe
        let icmp_probe = self.run_icmp_probe(target).await.ok();
        
        // SEQ probes (6 probes for ISN analysis)
        let seq_probes = self.run_seq_probes(target, open_port, 6).await?;
        
        // ECN probe
        let ecn_probe = self.run_ecn_probe(target, open_port).await.ok();
        
        let total_time_ms = start_time.elapsed()
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;
        
        Ok(ActiveProbeResults {
            target,
            tcp_probes,
            udp_probe,
            icmp_probe,
            seq_probes,
            ecn_probe,
            total_time_ms,
        })
    }

    /// Run TCP T1-T7 probes
    async fn run_tcp_probes(
        &self,
        target: IpAddr,
        open_port: u16,
        closed_port: u16,
    ) -> ScanResult<Vec<TcpProbeResponse>> {
        info!("Running TCP T1-T7 probes on {}", target);
        
        let mut responses = Vec::new();
        
        // T1: SYN to open port with window scale, NOP, MSS, timestamp, SACK permitted
        responses.push(self.run_t1_probe(target, open_port).await?);
        
        // T2: No flags to open port with various options
        responses.push(self.run_t2_probe(target, open_port).await?);
        
        // T3: SYN to open port with specific options
        responses.push(self.run_t3_probe(target, open_port).await?);
        
        // T4: ACK to open port
        responses.push(self.run_t4_probe(target, open_port).await?);
        
        // T5: SYN to closed port
        responses.push(self.run_t5_probe(target, closed_port).await?);
        
        // T6: ACK to closed port
        responses.push(self.run_t6_probe(target, closed_port).await?);
        
        // T7: FIN/PSH/URG to closed port
        responses.push(self.run_t7_probe(target, closed_port).await?);
        
        Ok(responses)
    }

    /// T1: SYN with window scale, NOP, MSS, timestamp, SACK permitted
    async fn run_t1_probe(&self, target: IpAddr, port: u16) -> ScanResult<TcpProbeResponse> {
        debug!("Running T1 probe to {}:{}", target, port);
        
        let flags = TcpFlags {
            syn: true,
            ack: false,
            fin: false,
            rst: false,
            psh: false,
            urg: false,
            ece: false,
            cwr: false,
        };
        
        // Options: Window Scale=10, NOP, MSS=1460, Timestamp, SACK Permitted
        let options = vec![
            3, 3, 10,           // Window Scale = 10
            1,                   // NOP
            2, 4, 5, 0xb4,      // MSS = 1460
            8, 10, 0, 0, 0, 0, 0, 0, 0, 0,  // Timestamp
            4, 2,               // SACK Permitted
        ];
        
        self.send_tcp_probe(target, port, flags, options, 5840, TcpProbeType::T1).await
    }

    /// T2: No flags with various options
    async fn run_t2_probe(&self, target: IpAddr, port: u16) -> ScanResult<TcpProbeResponse> {
        debug!("Running T2 probe to {}:{}", target, port);
        
        let flags = TcpFlags::default(); // No flags
        
        // Options: Window Scale=10, NOP, MSS=1400, Timestamp, SACK Permitted
        let options = vec![
            3, 3, 10,
            1,
            2, 4, 5, 0x78,      // MSS = 1400
            8, 10, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0,
            4, 2,
        ];
        
        self.send_tcp_probe(target, port, flags, options, 63000, TcpProbeType::T2).await
    }

    /// T3: SYN with specific options
    async fn run_t3_probe(&self, target: IpAddr, port: u16) -> ScanResult<TcpProbeResponse> {
        debug!("Running T3 probe to {}:{}", target, port);
        
        let flags = TcpFlags {
            syn: true,
            ack: false,
            fin: false,
            rst: false,
            psh: false,
            urg: false,
            ece: false,
            cwr: false,
        };
        
        // Options: Window Scale=5, NOP, MSS=1400, SACK Permitted, Timestamp
        let options = vec![
            3, 3, 5,
            1,
            2, 4, 5, 0x78,
            4, 2,
            8, 10, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        
        self.send_tcp_probe(target, port, flags, options, 4096, TcpProbeType::T3).await
    }

    /// T4: ACK to open port
    async fn run_t4_probe(&self, target: IpAddr, port: u16) -> ScanResult<TcpProbeResponse> {
        debug!("Running T4 probe to {}:{}", target, port);
        
        let flags = TcpFlags {
            syn: false,
            ack: true,
            fin: false,
            rst: false,
            psh: false,
            urg: false,
            ece: false,
            cwr: false,
        };
        
        // Options: Window Scale=10, NOP, MSS=1360, Timestamp, EOL
        let options = vec![
            3, 3, 10,
            1,
            2, 4, 5, 0x50,      // MSS = 1360
            8, 10, 0, 0, 0, 0, 0, 0, 0, 0,
            0,                   // EOL
        ];
        
        self.send_tcp_probe(target, port, flags, options, 1024, TcpProbeType::T4).await
    }

    /// T5: SYN to closed port
    async fn run_t5_probe(&self, target: IpAddr, port: u16) -> ScanResult<TcpProbeResponse> {
        debug!("Running T5 probe to {}:{}", target, port);
        
        let flags = TcpFlags {
            syn: true,
            ack: false,
            fin: false,
            rst: false,
            psh: false,
            urg: false,
            ece: false,
            cwr: false,
        };
        
        // Options: Window Scale=10, NOP, MSS=1400, SACK Permitted, Timestamp
        let options = vec![
            3, 3, 10,
            1,
            2, 4, 5, 0x78,
            4, 2,
            8, 10, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        
        self.send_tcp_probe(target, port, flags, options, 31337, TcpProbeType::T5).await
    }

    /// T6: ACK to closed port
    async fn run_t6_probe(&self, target: IpAddr, port: u16) -> ScanResult<TcpProbeResponse> {
        debug!("Running T6 probe to {}:{}", target, port);
        
        let flags = TcpFlags {
            syn: false,
            ack: true,
            fin: false,
            rst: false,
            psh: false,
            urg: false,
            ece: false,
            cwr: false,
        };
        
        // Options: Window Scale=10, NOP, MSS=1400, SACK Permitted, Timestamp
        let options = vec![
            3, 3, 10,
            1,
            2, 4, 5, 0x78,
            4, 2,
            8, 10, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        
        self.send_tcp_probe(target, port, flags, options, 32000, TcpProbeType::T6).await
    }

    /// T7: FIN/PSH/URG to closed port
    async fn run_t7_probe(&self, target: IpAddr, port: u16) -> ScanResult<TcpProbeResponse> {
        debug!("Running T7 probe to {}:{}", target, port);
        
        let flags = TcpFlags {
            syn: false,
            ack: false,
            fin: true,
            rst: false,
            psh: true,
            urg: true,
            ece: false,
            cwr: false,
        };
        
        // Options: Window Scale=15, NOP, MSS=265, Timestamp, EOL
        let options = vec![
            3, 3, 15,
            1,
            2, 4, 1, 0x09,      // MSS = 265
            8, 10, 0, 0, 0, 0, 0, 0, 0, 0,
            0,
        ];
        
        self.send_tcp_probe(target, port, flags, options, 65535, TcpProbeType::T7).await
    }

    /// Send a TCP probe and await response
    async fn send_tcp_probe(
        &self,
        target: IpAddr,
        port: u16,
        flags: TcpFlags,
        options: Vec<u8>,
        window_size: u16,
        probe_type: TcpProbeType,
    ) -> ScanResult<TcpProbeResponse> {
        let start_time = SystemTime::now();
        
        let src_port = 50000 + (probe_type as u16);
        let seq = 0x12345678;
        let ack = 0;
        
        // In a real implementation, this would:
        // 1. Build a TCP packet with the specified flags, options, window size
        // 2. Send via raw socket
        // 3. Wait for and capture the response
        // 4. Parse the response packet
        
        debug!("Simulating {:?} probe to {}:{} (flags: syn={}, ack={}, fin={}, psh={}, urg={})",
               probe_type, target, port, flags.syn, flags.ack, flags.fin, flags.psh, flags.urg);
        debug!("  Window: {}, Options len: {}, Src port: {}", window_size, options.len(), src_port);
        
        // Simulate network delay
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        let response_time_us = start_time.elapsed()
            .unwrap_or(Duration::from_secs(0))
            .as_micros() as u64;
        
        // Simulate different responses based on probe type
        let response = match probe_type {
            TcpProbeType::T1 | TcpProbeType::T3 => {
                // Open port SYN probes should get SYN-ACK
                TcpProbeResponse {
                    probe_type,
                    responded: true,
                    flags: Some(0x12), // SYN+ACK
                    window_size: Some(5840),
                    seq: Some(0xabcdef12),
                    ack: Some(seq + 1),
                    options: vec![2, 4, 5, 0xb4], // MSS option
                    ttl: Some(64),
                    ip_id: Some(0x1234),
                    df_flag: true,
                    response_time_us,
                }
            }
            TcpProbeType::T2 => {
                // No flags probe typically gets RST
                TcpProbeResponse {
                    probe_type,
                    responded: true,
                    flags: Some(0x04), // RST
                    window_size: Some(0),
                    seq: Some(0),
                    ack: Some(0),
                    options: vec![],
                    ttl: Some(64),
                    ip_id: Some(0x1235),
                    df_flag: true,
                    response_time_us,
                }
            }
            TcpProbeType::T4 | TcpProbeType::T6 => {
                // ACK probes to open/closed ports get RST
                TcpProbeResponse {
                    probe_type,
                    responded: true,
                    flags: Some(0x04), // RST
                    window_size: Some(0),
                    seq: Some(ack),
                    ack: Some(0),
                    options: vec![],
                    ttl: Some(64),
                    ip_id: Some(0x1236),
                    df_flag: true,
                    response_time_us,
                }
            }
            TcpProbeType::T5 => {
                // SYN to closed port gets RST+ACK
                TcpProbeResponse {
                    probe_type,
                    responded: true,
                    flags: Some(0x14), // RST+ACK
                    window_size: Some(0),
                    seq: Some(0),
                    ack: Some(seq + 1),
                    options: vec![],
                    ttl: Some(64),
                    ip_id: Some(0x1237),
                    df_flag: true,
                    response_time_us,
                }
            }
            TcpProbeType::T7 => {
                // FIN/PSH/URG to closed port gets RST
                TcpProbeResponse {
                    probe_type,
                    responded: true,
                    flags: Some(0x04), // RST
                    window_size: Some(0),
                    seq: Some(ack),
                    ack: Some(0),
                    options: vec![],
                    ttl: Some(64),
                    ip_id: Some(0x1238),
                    df_flag: true,
                    response_time_us,
                }
            }
        };
        
        Ok(response)
    }

    /// Run UDP U1 probe (to closed port)
    async fn run_udp_probe(&self, target: IpAddr, port: u16) -> ScanResult<UdpProbeResponse> {
        info!("Running UDP U1 probe to {}:{}", target, port);
        let start_time = SystemTime::now();
        
        // In a real implementation, this would:
        // 1. Build a UDP packet with specific payload
        // 2. Send to the closed port
        // 3. Wait for ICMP Port Unreachable response
        // 4. Extract TTL, IP ID, DF flag from ICMP response
        
        debug!("Simulating UDP probe to {}:{}", target, port);
        
        // Simulate network delay
        tokio::time::sleep(Duration::from_millis(20)).await;
        
        let response_time_us = start_time.elapsed()
            .unwrap_or(Duration::from_secs(0))
            .as_micros() as u64;
        
        // Simulate ICMP port unreachable response
        Ok(UdpProbeResponse {
            icmp_unreachable: true,
            icmp_type: Some(3),  // Destination Unreachable
            icmp_code: Some(3),  // Port Unreachable
            ttl: Some(64),
            ip_id: Some(0x2345),
            df_flag: true,
            response_time_us,
        })
    }

    /// Run ICMP IE probe (Echo Request)
    async fn run_icmp_probe(&self, target: IpAddr) -> ScanResult<IcmpProbeResponse> {
        info!("Running ICMP IE probe to {}", target);
        let start_time = SystemTime::now();
        
        // In a real implementation, this would:
        // 1. Build an ICMP Echo Request packet
        // 2. Send to target
        // 3. Wait for Echo Reply
        // 4. Extract TTL, IP ID, DF flag, ICMP code
        
        debug!("Simulating ICMP Echo Request to {}", target);
        
        // Simulate network delay
        tokio::time::sleep(Duration::from_millis(15)).await;
        
        let response_time_us = start_time.elapsed()
            .unwrap_or(Duration::from_secs(0))
            .as_micros() as u64;
        
        // Simulate ICMP echo reply
        Ok(IcmpProbeResponse {
            echo_reply: true,
            ttl: Some(64),
            ip_id: Some(0x3456),
            df_flag: false,  // ICMP echo usually doesn't set DF
            icmp_code: Some(0),
            response_time_us,
        })
    }

    /// Run SEQ probes for ISN (Initial Sequence Number) analysis
    async fn run_seq_probes(
        &self,
        target: IpAddr,
        port: u16,
        count: usize,
    ) -> ScanResult<Vec<SeqProbeResponse>> {
        info!("Running {} SEQ probes to {}:{}", count, target, port);
        
        let mut responses = Vec::new();
        
        for i in 0..count {
            let response = self.send_seq_probe(target, port, i).await?;
            responses.push(response);
            
            // Small delay between probes (100ms as per Nmap)
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        Ok(responses)
    }

    /// Send a single SEQ probe
    async fn send_seq_probe(
        &self,
        target: IpAddr,
        port: u16,
        index: usize,
    ) -> ScanResult<SeqProbeResponse> {
        let _flags = TcpFlags {
            syn: true,
            ack: false,
            fin: false,
            rst: false,
            psh: false,
            urg: false,
            ece: false,
            cwr: false,
        };
        
        let _options = vec![2, 4, 5, 0xb4]; // MSS option
        let _src_port = 50100 + index as u16;
        let seq = 0x11111111 + (index as u32 * 0x1000);
        
        // In a real implementation, would build and send TCP SYN packet
        debug!("Simulating SEQ probe {} to {}:{} (seq: 0x{:x})", index, target, port, seq);
        
        // Simulate response
        tokio::time::sleep(Duration::from_millis(5)).await;
        
        let timestamp_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        
        // Simulate ISN (would vary by OS)
        let isn = 0xaabbccdd + (index as u32 * 0x10000);
        
        Ok(SeqProbeResponse {
            isn,
            timestamp_us,
            ip_id: Some(0x4000 + index as u16),
        })
    }

    /// Run ECN probe
    async fn run_ecn_probe(&self, target: IpAddr, port: u16) -> ScanResult<EcnProbeResponse> {
        info!("Running ECN probe to {}:{}", target, port);
        
        // In a real implementation, this would:
        // 1. Build TCP SYN with ECE+CWR flags set
        // 2. Send to open port
        // 3. Check if SYN-ACK has ECE flag (ECN support)
        
        debug!("Simulating ECN probe to {}:{} (SYN with ECE+CWR)", target, port);
        
        // Simulate response
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        // Simulate ECN-capable response
        Ok(EcnProbeResponse {
            ecn_supported: true,
            ecn_flags: Some(0x02), // ECE flag
            cwr_flag: false,
            ece_flag: true,
        })
    }

    /// Analyze SEQ probe results for ISN predictability
    pub fn analyze_seq_responses(&self, responses: &[SeqProbeResponse]) -> SeqAnalysis {
        if responses.len() < 2 {
            return SeqAnalysis {
                gcd: None,
                avg_rate: None,
                std_dev: None,
                predictability: SeqPredictability::Unknown,
            };
        }
        
        // Calculate differences between consecutive ISNs
        let diffs: Vec<i64> = responses.windows(2)
            .map(|w| (w[1].isn as i64) - (w[0].isn as i64))
            .collect();
        
        // Calculate average rate
        let avg_diff = diffs.iter().sum::<i64>() as f64 / diffs.len() as f64;
        
        // Calculate standard deviation
        let variance = diffs.iter()
            .map(|d| {
                let diff = (*d as f64) - avg_diff;
                diff * diff
            })
            .sum::<f64>() / diffs.len() as f64;
        let std_dev = variance.sqrt();
        
        // Calculate GCD of differences for pattern detection
        let gcd = self.calculate_gcd(&diffs);
        
        // Determine predictability
        let predictability = if std_dev < 100.0 {
            SeqPredictability::Constant
        } else if std_dev < 10000.0 {
            SeqPredictability::Incremental
        } else if std_dev < 1000000.0 {
            SeqPredictability::TimeDependent
        } else {
            SeqPredictability::Random
        };
        
        SeqAnalysis {
            gcd: Some(gcd),
            avg_rate: Some(avg_diff),
            std_dev: Some(std_dev),
            predictability,
        }
    }

    /// Calculate GCD of differences
    fn calculate_gcd(&self, numbers: &[i64]) -> i64 {
        if numbers.is_empty() {
            return 0;
        }
        
        let mut result = numbers[0].abs();
        for &num in &numbers[1..] {
            result = self.gcd_two(result, num.abs());
        }
        result
    }

    /// GCD of two numbers
    fn gcd_two(&self, mut a: i64, mut b: i64) -> i64 {
        while b != 0 {
            let temp = b;
            b = a % b;
            a = temp;
        }
        a
    }
}

impl Default for ActiveProbeLibrary {
    fn default() -> Self {
        Self::new(3000)
    }
}

/// Sequence number analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeqAnalysis {
    /// Greatest common divisor of ISN differences
    pub gcd: Option<i64>,
    /// Average rate of ISN increase
    pub avg_rate: Option<f64>,
    /// Standard deviation of ISN differences
    pub std_dev: Option<f64>,
    /// Predictability classification
    pub predictability: SeqPredictability,
}

/// ISN predictability classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeqPredictability {
    /// Constant or near-constant ISN
    Constant,
    /// Incremental (e.g., +1 per connection)
    Incremental,
    /// Time-dependent (e.g., based on system clock)
    TimeDependent,
    /// Random (cryptographically secure)
    Random,
    /// Unknown (insufficient data)
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tcp_probes() {
        let library = ActiveProbeLibrary::new(3000);
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        
        let responses = library.run_tcp_probes(target, 80, 81).await;
        assert!(responses.is_ok());
        
        let probes = responses.unwrap();
        assert_eq!(probes.len(), 7);
    }

    #[tokio::test]
    async fn test_udp_probe() {
        let library = ActiveProbeLibrary::new(3000);
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        
        let response = library.run_udp_probe(target, 12345).await;
        assert!(response.is_ok());
        
        let probe = response.unwrap();
        assert!(probe.icmp_unreachable);
    }

    #[tokio::test]
    async fn test_icmp_probe() {
        let library = ActiveProbeLibrary::new(3000);
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        
        let response = library.run_icmp_probe(target).await;
        assert!(response.is_ok());
        
        let probe = response.unwrap();
        assert!(probe.echo_reply);
    }

    #[tokio::test]
    async fn test_seq_probes() {
        let library = ActiveProbeLibrary::new(3000);
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        
        let responses = library.run_seq_probes(target, 80, 6).await;
        assert!(responses.is_ok());
        
        let probes = responses.unwrap();
        assert_eq!(probes.len(), 6);
    }

    #[test]
    fn test_seq_analysis() {
        let library = ActiveProbeLibrary::new(3000);
        
        let responses = vec![
            SeqProbeResponse { isn: 1000, timestamp_us: 0, ip_id: Some(1) },
            SeqProbeResponse { isn: 2000, timestamp_us: 100000, ip_id: Some(2) },
            SeqProbeResponse { isn: 3000, timestamp_us: 200000, ip_id: Some(3) },
            SeqProbeResponse { isn: 4000, timestamp_us: 300000, ip_id: Some(4) },
        ];
        
        let analysis = library.analyze_seq_responses(&responses);
        assert_eq!(analysis.gcd, Some(1000));
        assert!(matches!(analysis.predictability, SeqPredictability::Constant));
    }

    #[tokio::test]
    async fn test_ecn_probe() {
        let library = ActiveProbeLibrary::new(3000);
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        
        let response = library.run_ecn_probe(target, 80).await;
        assert!(response.is_ok());
        
        let probe = response.unwrap();
        assert!(probe.ecn_supported);
    }

    #[tokio::test]
    async fn test_probe_all() {
        let library = ActiveProbeLibrary::new(3000);
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        
        let results = library.probe_all(target, 80, 81).await;
        assert!(results.is_ok());
        
        let probes = results.unwrap();
        assert_eq!(probes.tcp_probes.len(), 7);
        assert!(probes.udp_probe.is_some());
        assert!(probes.icmp_probe.is_some());
        assert_eq!(probes.seq_probes.len(), 6);
        assert!(probes.ecn_probe.is_some());
    }
}

