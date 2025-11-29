# Clock Skew Analysis & Passive Fingerprinting - Complete Implementation

## Overview

This document details the implementation of advanced OS fingerprinting techniques:
- **Clock Skew Analysis**: TCP timestamp-based clock behavior analysis
- **Passive Fingerprinting**: Non-intrusive traffic observation techniques

These techniques provide additional OS detection capabilities with varying levels of stealth and accuracy.

---

## 1. Clock Skew Analysis

### Purpose
Clock skew analysis examines the rate at which a remote system's TCP timestamp counter increments. Different operating systems and hardware platforms exhibit distinct clock behaviors that can be used for OS identification.

### Implementation Details

#### Module: `src/os_fingerprint/clock_skew.rs`

**Key Components:**

1. **TimestampMeasurement**
   - Captures TCP timestamp values
   - Records local time for correlation
   - Tracks packet sequence for ordering

2. **ClockSkewAnalyzer**
   - Collects multiple timestamp samples
   - Performs linear regression analysis
   - Estimates clock skew in parts per million (ppm)
   - Calculates clock frequency in Hz

3. **ClockSkewAnalysis Results**
   - Estimated clock skew (ppm)
   - Clock frequency (Hz)
   - Standard deviation
   - OS classification hints
   - Confidence score

### Techniques Implemented

#### 1. TCP Timestamp Delta Collection
```rust
pub async fn collect_timestamps(
    &self,
    target: IpAddr,
    port: u16,
    num_samples: usize,
) -> ScanResult<Vec<TimestampMeasurement>>
```

**Features:**
- Sends multiple TCP probes to collect timestamps
- Configurable sample count
- Time-bounded collection (max 30 seconds)
- Validates minimum sample requirements

#### 2. Skew Curve Estimation
```rust
pub fn estimate_skew(
    &self,
    measurements: &[TimestampMeasurement],
) -> ScanResult<(f64, f64, f64)>
```

**Algorithm:**
- Linear regression: y = mx + b
- y = remote_timestamp, x = local_time
- Slope (m) represents clock frequency ratio
- Skew = (slope - 1.0) × 1,000,000 ppm
- Calculates standard deviation of residuals

**Mathematical Approach:**
```
slope = (n × Σxy - Σx × Σy) / (n × Σx² - (Σx)²)
skew_ppm = (slope - 1.0) × 1,000,000
clock_frequency_hz = slope × 1,000,000
```

#### 3. OS Classification via Clock Behaviour
```rust
pub fn classify_os_by_clock(
    &self,
    skew_ppm: f64,
    clock_frequency_hz: f64,
    std_dev: f64,
) -> Vec<String>
```

**Classification Rules:**

| Clock Frequency | OS Hints |
|----------------|----------|
| ~1000 Hz | Linux (HZ=1000) or macOS |
| ~250 Hz | Linux (HZ=250) |
| ~100 Hz | Linux (HZ=100), Windows, or BSD |
| ~64 Hz | Windows (legacy timer) |

**Stability Indicators:**
- `std_dev < 100`: Stable clock (server-grade hardware)
- `std_dev > 1000`: Unstable clock (virtualized/embedded)

**Synchronization:**
- `|skew_ppm| < 10`: Well-synchronized (NTP enabled)
- `|skew_ppm| > 100`: Poorly synchronized

### Usage Example

```rust
use nrmap::os_fingerprint::ClockSkewAnalyzer;
use std::net::IpAddr;

let analyzer = ClockSkewAnalyzer::new();
let target: IpAddr = "192.168.1.100".parse()?;

let analysis = analyzer.analyze(target, 80, 20).await?;

println!("Clock skew: {:.2} ppm", analysis.skew_ppm.unwrap());
println!("Clock frequency: {:.2} Hz", analysis.clock_frequency_hz.unwrap());
println!("Confidence: {:.2}%", analysis.confidence * 100.0);

for hint in &analysis.os_hints {
    println!("  - {}", hint);
}
```

### Configuration

```toml
[os_fingerprint]
enable_clock_skew = true
clock_skew_samples = 20
```

---

## 2. Passive Fingerprinting

### Purpose
Passive fingerprinting analyzes network traffic without sending active probes. This is the stealthiest OS detection method as it leaves no footprint on the target system.

### Implementation Details

#### Module: `src/os_fingerprint/passive.rs`

**Key Components:**

1. **PassiveObservation**
   - Captures packet metadata
   - Records TTL, window size, MSS
   - Stores TCP options and flags
   - Timestamps observations

2. **PassiveAnalyzer**
   - Accumulates observations per target
   - Analyzes TTL + MSS patterns
   - Examines TCP handshake behavior
   - Estimates system uptime

3. **PassiveFingerprintResult**
   - TTL + MSS profile
   - Handshake pattern analysis
   - Uptime estimation
   - OS classification hints
   - Confidence scoring

### Techniques Implemented

#### 1. TTL + MSS Passive Observation
```rust
pub fn analyze_ttl_mss(&self, target: IpAddr) -> ScanResult<TtlMssProfile>
```

**Analyzed Attributes:**
- **Initial TTL**: Most common TTL value observed
- **MSS (Maximum Segment Size)**: TCP option value
- **Window Size**: TCP window from packets
- **DF Flag**: Don't Fragment bit setting

**TTL-Based OS Hints:**
| TTL Value | OS Hints |
|-----------|----------|
| 64 | Linux, macOS, or Unix-like |
| 128 | Windows |
| 255 | Cisco IOS or legacy Unix |

**MSS-Based Hints:**
| MSS Value | Indication |
|-----------|------------|
| 1460 | Ethernet MTU 1500 (standard) |
| 1380 | VPN or tunneled connection |
| 1440 | PPPoE connection |

#### 2. TCP Handshake Pattern Analysis
```rust
pub fn analyze_handshake_pattern(&self, target: IpAddr) -> ScanResult<HandshakePattern>
```

**Analyzed Patterns:**
- **SYN Window Size**: Average window in SYN packets
- **SYN-ACK Window Size**: Average window in SYN-ACK packets
- **TCP Options Sequence**: Most common option ordering
- **Window Scale Factor**: Extracted from TCP options

**Window Scale Interpretation:**
| Scale Factor | OS Hints |
|--------------|----------|
| ≥ 7 | Linux (aggressive window scaling) |
| 2-6 | Windows or macOS |

#### 3. Passive Uptime Estimation
```rust
pub fn estimate_uptime(&self, target: IpAddr) -> ScanResult<Duration>
```

**Method:**
- Analyzes TCP timestamp options
- Calculates timestamp increment rate
- Estimates system uptime based on timestamp value
- Accounts for clock frequency variations

### Usage Example

```rust
use nrmap::os_fingerprint::{PassiveAnalyzer, PassiveObservation};
use std::net::IpAddr;

let mut analyzer = PassiveAnalyzer::new();

// Add observations from packet capture
for packet in captured_packets {
    let observation = PassiveObservation {
        src_ip: packet.src_ip,
        dst_ip: packet.dst_ip,
        src_port: packet.src_port,
        dst_port: packet.dst_port,
        ttl: packet.ttl,
        window_size: packet.window,
        mss: packet.extract_mss(),
        tcp_options: packet.tcp_options(),
        tcp_flags: packet.flags,
        timestamp_us: packet.timestamp,
        df_flag: packet.df_flag,
    };
    analyzer.add_observation(observation);
}

// Analyze collected data
let target: IpAddr = "192.168.1.100".parse()?;
let result = analyzer.analyze(target)?;

println!("Packets observed: {}", result.packets_observed);
println!("Confidence: {:.2}%", result.confidence * 100.0);

if let Some(profile) = result.ttl_mss_profile {
    println!("TTL: {}, MSS: {}", profile.initial_ttl, profile.mss);
}

for hint in &result.os_hints {
    println!("  - {}", hint);
}
```

### Configuration

```toml
[os_fingerprint]
enable_passive = false  # Requires packet capture capability
passive_min_observations = 10
```

---

## 3. Integration with OS Fingerprinting Engine

Both techniques are integrated into the main `OsFingerprintEngine`:

```rust
pub struct OsFingerprintEngine {
    tcp_analyzer: TcpFingerprintAnalyzer,
    icmp_analyzer: IcmpFingerprintAnalyzer,
    udp_analyzer: UdpFingerprintAnalyzer,
    protocol_analyzer: ProtocolHintsAnalyzer,
    clock_skew_analyzer: ClockSkewAnalyzer,      // New
    passive_analyzer: PassiveAnalyzer,            // New
    database: OsFingerprintDatabase,
    matcher: OsMatcher,
}
```

### Complete Fingerprint Structure

```rust
pub struct OsFingerprint {
    pub target: IpAddr,
    pub tcp_fingerprint: Option<TcpFingerprint>,
    pub icmp_fingerprint: Option<IcmpFingerprint>,
    pub udp_fingerprint: Option<UdpFingerprint>,
    pub protocol_hints: Option<ProtocolHints>,
    pub clock_skew: Option<ClockSkewAnalysis>,         // New
    pub passive_fingerprint: Option<PassiveFingerprintResult>,  // New
    pub detection_time_ms: u64,
}
```

---

## 4. Error Handling

New error variants added to support these techniques:

```rust
pub enum ScanError {
    // ... existing variants ...
    
    /// Insufficient data for analysis
    #[error("Insufficient data: required {required}, available {available}")]
    InsufficientData { required: usize, available: usize },

    /// Target not found in collected data
    #[error("Target not found: {target}")]
    TargetNotFound { target: IpAddr },
}
```

---

## 5. Testing

### Clock Skew Tests

```bash
# Test clock skew collection
cargo test test_clock_skew_collection

# Test skew estimation with synthetic data
cargo test test_skew_estimation

# Test OS classification
cargo test test_os_classification

# Test confidence calculation
cargo test test_confidence_calculation
```

### Passive Fingerprinting Tests

```bash
# Test passive observation
cargo test test_passive_observation

# Test TTL+MSS analysis
cargo test test_ttl_mss_analysis

# Test OS classification
cargo test test_os_classification

# Test complete passive analysis
cargo test test_passive_analysis
```

---

## 6. Performance Characteristics

### Clock Skew Analysis

| Metric | Value |
|--------|-------|
| Sample Collection Time | 2-30 seconds (configurable) |
| Network Overhead | Low (20-30 packets) |
| Accuracy | High (with sufficient samples) |
| Stealth Level | Low (active probing) |
| Resource Usage | Minimal CPU, memory |

**Pros:**
- High accuracy with good samples
- Deterministic analysis
- Hardware-level fingerprinting

**Cons:**
- Requires active probing
- Detectable by IDS/IPS
- Needs open TCP port

### Passive Fingerprinting

| Metric | Value |
|--------|-------|
| Collection Time | Variable (depends on traffic) |
| Network Overhead | None (passive observation) |
| Accuracy | Medium (depends on observations) |
| Stealth Level | Very High (completely passive) |
| Resource Usage | Low CPU, moderate memory |

**Pros:**
- Completely stealthy
- No network footprint
- Can monitor multiple targets
- Long-term observation possible

**Cons:**
- Requires packet capture capability
- Depends on target generating traffic
- Lower accuracy with few observations
- May need elevated privileges

---

## 7. Comparison Matrix

| Technique | Stealth | Accuracy | Speed | Complexity |
|-----------|---------|----------|-------|------------|
| TCP/IP Stack | Low | High | Fast | Medium |
| ICMP-Based | Medium | High | Fast | Low |
| UDP-Based | Medium | Medium | Medium | Medium |
| Protocol Hints | Low | Medium | Slow | High |
| **Clock Skew** | **Low** | **High** | **Slow** | **High** |
| **Passive** | **Very High** | **Medium** | **Varies** | **Medium** |

---

## 8. Use Cases

### Clock Skew Analysis
- **Server fingerprinting**: Identify server OS and hardware
- **Load balancer detection**: Detect multiple backend servers
- **Virtual machine detection**: Identify VM clock behavior
- **Network device classification**: Distinguish routers, switches, firewalls

### Passive Fingerprinting
- **Security monitoring**: Identify unauthorized devices on network
- **Network visibility**: Continuous OS inventory without scanning
- **Threat hunting**: Detect anomalous systems
- **Compliance auditing**: Verify OS versions passively

---

## 9. Example Output

### Clock Skew Analysis Output

```
✓ Clock Skew Analysis Results:
  Target: 192.168.1.100
  Samples collected: 20
  Clock skew: 12.45 ppm
  Clock frequency: 1000.12 Hz
  Standard deviation: 45.23
  Confidence: 87.50%
  OS Hints:
    - Linux (HZ=1000) or macOS
    - Stable clock (server-grade hardware)
    - Well-synchronized clock (NTP enabled)
```

### Passive Fingerprinting Output

```
✓ Complete Passive Fingerprint:
  Packets observed: 15
  Confidence: 85.00%
  
  TTL + MSS Profile:
    Initial TTL: 64
    MSS: 1460
    Window size: 65535
    DF flag set: true
  
  Handshake Pattern:
    SYN window average: 65535
    SYN-ACK window average: 65535
    TCP options: [2, 4, 5, 180, 1, 3, 3, 7]
    Window scale: 7
  
  Estimated Uptime: 5d 12h 34m
  
  OS Hints:
    - Linux, macOS, or Unix-like
    - Ethernet MTU 1500 (common)
    - High-performance TCP stack
    - Modern OS with PMTU discovery
    - Linux (high window scaling)
```

---

## 10. Files Added/Modified

### New Files
- `src/os_fingerprint/clock_skew.rs` (492 lines)
- `src/os_fingerprint/passive.rs` (528 lines)
- `examples/advanced_os_fingerprint.rs` (236 lines)

### Modified Files
- `src/os_fingerprint/mod.rs`: Integrated new analyzers
- `src/error.rs`: Added new error variants
- `config.toml`: Added configuration options
- `PRD.md`: Marked features as completed

---

## 11. Build Status

```bash
✓ Compilation: SUCCESS
✓ Warnings: 0
✓ Tests: All passing
✓ Documentation: Complete
✓ Examples: Functional
```

**Build Statistics:**
- Total lines added: ~1,400
- New modules: 2
- New examples: 1
- Build time: ~5 seconds (release)

---

## 12. Next Steps

### Potential Enhancements
1. **Active Probe Library** (PRD lines 128-132)
   - TCP T1–T7 Probe Set
   - UDP U1 Probe
   - ICMP IE Probe
   - SEQ / ECN Probes

2. **Enhanced Database** (PRD lines 134-137)
   - JSON/YAML Fingerprint Schema
   - Fuzzy Matching Engine
   - Confidence Scoring improvements

### Integration Opportunities
- Combine clock skew with TCP fingerprinting for higher confidence
- Use passive fingerprinting as initial triage before active probing
- Correlate multiple techniques for composite OS detection

---

## Conclusion

The Clock Skew Analysis and Passive Fingerprinting modules are now fully implemented, tested, and integrated into the NrMAP OS fingerprinting engine. These advanced techniques provide:

1. **Clock Skew Analysis**: Hardware-level OS detection through TCP timestamp behavior analysis
2. **Passive Fingerprinting**: Completely stealthy OS detection through traffic observation

Both modules include:
- ✅ Comprehensive error handling
- ✅ Detailed logging with tracing
- ✅ Unit tests for core functionality
- ✅ Integration with main engine
- ✅ Configuration options
- ✅ Example code
- ✅ Complete documentation

The implementation maintains the high quality standards of the project with production-ready code, extensive testing, and thorough documentation.

