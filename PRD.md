# 🛡️ RustScan — High-Level Product Requirements Document (PRD)

---

## 📌 Objective

Build a **high-performance, Nmap-like network scanner** in Rust that focuses on:  
- Fast scanning  
- Async parallelism  
- Accurate port & service detection  
- Extensible plugin-based architecture  
- Modern CLI + API integration  
- Safe for enterprise & cloud environments  

---

## 🎯 Scope (MVP)

- TCP/UDP scanning  
- Basic service detection  
- Simple OS fingerprinting  
- Parallel async scanning engine  
- JSON/YAML output  
- CLI-based operations  
- Modular crate architecture  

---

## 🏗️ Architecture Overview

- **Scanner Engine**
  - Async runtime (Tokio)
  - Raw socket + packet crafting layer
  - Adaptive rate control

- **Detection Engine**
  - Port scanner
  - Service probe registry
  - OS fingerprint heuristics

- **Output Engine**
  - JSON / YAML reporters
  - Table formatter

- **CLI Layer**
  - nmap-like commands
  - Profiles & presets

- **API Layer (Optional)**
  - REST / gRPC microservice for distributed scanning

---

## 🔧 Module Breakdown

- [x] `scanner-core` ✅ **COMPLETE**
  - [x] Host discovery
  - [x] TCP connect scan  
  - [x] TCP SYN scan  
  - [x] UDP scan  
  - [x] Adaptive throttling  

- [x] `packet-engine` ✅ **COMPLETE**
  - [x] Raw socket abstraction  
  - [x] Packet crafting  
  - [x] Packet parser  

- [x] `detection-engine` ✅ **COMPLETE**
  - [x] Service banner grabbing  
  - [x] Fingerprint matching  
  - [x] OS heuristics  
 
- [x] `distributed` ✅ **COMPLETE**
  - [x] Scan scheduler  
  - [x] Agent mode  
  - [x] Result aggregator  

- [x] `report-engine` ✅ **COMPLETE**
  - [x] JSON output  
  - [x] YAML output  
  - [x] HTML (optional)  
  - [x] CLI table view 

- [x] `cli` ✅ **COMPLETE**
  - [x] Flags  
  - [x] Profiles  
  - [x] Output formatting  

# ✅ OS Fingerprinting — Core Feature Checklist (MVP) ✅ **COMPLETE**

- [x] TCP/IP Stack Fingerprinting
- [x] Initial TTL Analysis
- [x] TCP Window Size Analysis
- [x] MSS + TCP Options Ordering
- [x] DF (Don't Fragment) Flag Behaviour
- [x] SYN/ACK Response Patterning
- [x] RST Packet Behaviour
- [x] IP ID Increment Pattern Detection
- [x] ECN/CWR Response Analysis

- [x] ICMP-Based Fingerprinting
- [x] ICMP Echo Reply Structure
- [x] ICMP Unreachable Codes
- [x] ICMP Timestamp Behaviour
- [x] ICMP Rate-Limiting Fingerprints

- [x] UDP Fingerprinting ✅
- [x] Port Unreachable Behaviour
- [x] ICMP Payload Echoing
- [x] Silent Drop vs Respond Patterns

- [x] Protocol & Service OS Hints ✅
- [x] SSH Banner Fingerprinting
- [x] SMB OS Detection
- [x] HTTP Header & Timestamp Clues
- [x] TLS Fingerprint Extraction

- [x] Clock Skew Analysis
- [x] TCP Timestamp Delta Collection
- [x] Skew Curve Estimation
- [x] OS Classification via Clock Behaviour

- [x] Passive Fingerprinting (Optional)
- [x] TTL + MSS Passive Observation
- [x] TCP Handshake Pattern Analysis
- [x] Passive Uptime Estimation

- [x] Active Probe Library
- [x] TCP T1–T7 Probe Set
- [x] UDP U1 Probe
- [x] ICMP IE Probe
- [x] SEQ / ECN Probes

- [x] OS Fingerprint Database
- [x] JSON/YAML Fingerprint Schema
- [x] Fuzzy Matching Engine
- [x] Confidence Scoring
- [x] Closest-Match Suggestions

- [x] Output & Reporting
- [x] OS Guess + Accuracy
- [x] Matched Fingerprints
- [x] Mismatched Fingerprints
- [x] Confidence Level Output


---

## 📡 API Specifications (Optional)

### **POST /scan**
Submit a scan job
```json
{
  "targets": ["192.168.1.1"],
  "ports": "1-1000",
  "scan_type": "syn",
  "profile": "fast"
}


rustscan/
 ├── Cargo.toml
 ├── src/
 │   ├── main.rs
 │   ├── cli/
 │   │   └── mod.rs
 │   ├── scanner/
 │   │   ├── syn_scan.rs
 │   │   ├── tcp_connect.rs
 │   │   ├── udp_scan.rs
 │   │   └── host_discovery.rs
 │   ├── packet/
 │   │   ├── builder.rs
 │   │   └── parser.rs
 │   ├── detection/
 │   │   ├── banner.rs
 │   │   ├── fingerprint.rs
 │   │   └── os.rs
 │   ├── report/
 │   │   ├── json.rs
 │   │   ├── yaml.rs
 │   │   └── table.rs
 │   └── api/ (optional)
 │       ├── rest.rs
 │       ├── grpc.rs
 │       └── ws.rs
 └── tests/

