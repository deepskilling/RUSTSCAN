/// Packet crafting module for creating network packets
/// 
/// Provides builders and utilities for crafting TCP, UDP, ICMP, and IP packets
/// with proper checksums and header fields.

use crate::error::{ScanError, ScanResult};
use std::net::{IpAddr, Ipv4Addr};
use tracing::{debug, trace};

/// TCP packet structure
#[derive(Debug, Clone)]
pub struct TcpPacket {
    pub source_port: u16,
    pub dest_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub urgent_pointer: u16,
    pub options: Vec<u8>,
    pub payload: Vec<u8>,
}

/// TCP flags
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    /// Create flags for a SYN packet
    pub fn syn() -> Self {
        Self {
            syn: true,
            ..Default::default()
        }
    }

    /// Create flags for a SYN-ACK packet
    pub fn syn_ack() -> Self {
        Self {
            syn: true,
            ack: true,
            ..Default::default()
        }
    }

    /// Create flags for an ACK packet
    pub fn ack() -> Self {
        Self {
            ack: true,
            ..Default::default()
        }
    }

    /// Create flags for a RST packet
    pub fn rst() -> Self {
        Self {
            rst: true,
            ..Default::default()
        }
    }

    /// Convert flags to u8 value
    pub fn to_u8(&self) -> u8 {
        let mut flags = 0u8;
        if self.fin { flags |= 0x01; }
        if self.syn { flags |= 0x02; }
        if self.rst { flags |= 0x04; }
        if self.psh { flags |= 0x08; }
        if self.ack { flags |= 0x10; }
        if self.urg { flags |= 0x20; }
        if self.ece { flags |= 0x40; }
        if self.cwr { flags |= 0x80; }
        flags
    }

    /// Parse flags from u8 value
    pub fn from_u8(flags: u8) -> Self {
        Self {
            fin: (flags & 0x01) != 0,
            syn: (flags & 0x02) != 0,
            rst: (flags & 0x04) != 0,
            psh: (flags & 0x08) != 0,
            ack: (flags & 0x10) != 0,
            urg: (flags & 0x20) != 0,
            ece: (flags & 0x40) != 0,
            cwr: (flags & 0x80) != 0,
        }
    }
}

/// UDP packet structure
#[derive(Debug, Clone)]
pub struct UdpPacket {
    pub source_port: u16,
    pub dest_port: u16,
    pub payload: Vec<u8>,
}

/// ICMP packet structure
#[derive(Debug, Clone)]
pub struct IcmpPacket {
    pub icmp_type: u8,
    pub code: u8,
    pub identifier: u16,
    pub sequence: u16,
    pub payload: Vec<u8>,
}

impl IcmpPacket {
    /// Create an ICMP Echo Request (ping)
    pub fn echo_request(identifier: u16, sequence: u16) -> Self {
        Self {
            icmp_type: 8,  // Echo Request
            code: 0,
            identifier,
            sequence,
            payload: vec![0; 56],  // Standard ping payload size
        }
    }

    /// Create an ICMP Echo Reply
    pub fn echo_reply(identifier: u16, sequence: u16) -> Self {
        Self {
            icmp_type: 0,  // Echo Reply
            code: 0,
            identifier,
            sequence,
            payload: vec![0; 56],
        }
    }
}

/// Packet builder for constructing network packets
pub struct PacketBuilder {
    source_ip: Option<IpAddr>,
    dest_ip: Option<IpAddr>,
    ttl: u8,
    protocol: Option<u8>,
}

impl PacketBuilder {
    /// Create a new packet builder
    pub fn new() -> Self {
        debug!("Creating new packet builder");
        Self {
            source_ip: None,
            dest_ip: None,
            ttl: 64,
            protocol: None,
        }
    }

    /// Set source IP address
    pub fn source(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    /// Set destination IP address
    pub fn destination(mut self, ip: IpAddr) -> Self {
        self.dest_ip = Some(ip);
        self
    }

    /// Set TTL (Time To Live)
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    /// Set IP protocol
    pub fn protocol(mut self, protocol: u8) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Build a TCP packet
    pub fn build_tcp(&self, tcp: &TcpPacket) -> ScanResult<Vec<u8>> {
        trace!("Building TCP packet: {:?}", tcp);

        let dest_ip = self.dest_ip.ok_or_else(|| {
            ScanError::packet_error("Destination IP not set")
        })?;

        let source_ip = self.source_ip.unwrap_or_else(|| {
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
        });

        // Create TCP header (20 bytes minimum)
        let mut packet = Vec::with_capacity(20 + tcp.options.len() + tcp.payload.len());

        // Source port (2 bytes)
        packet.extend_from_slice(&tcp.source_port.to_be_bytes());
        
        // Destination port (2 bytes)
        packet.extend_from_slice(&tcp.dest_port.to_be_bytes());
        
        // Sequence number (4 bytes)
        packet.extend_from_slice(&tcp.sequence.to_be_bytes());
        
        // Acknowledgment number (4 bytes)
        packet.extend_from_slice(&tcp.acknowledgment.to_be_bytes());
        
        // Data offset (4 bits) + Reserved (3 bits) + Flags (9 bits) = 2 bytes
        let data_offset = ((20 + tcp.options.len()) / 4) as u8;
        packet.push((data_offset << 4) | 0);
        packet.push(tcp.flags.to_u8());
        
        // Window size (2 bytes)
        packet.extend_from_slice(&tcp.window.to_be_bytes());
        
        // Checksum (2 bytes) - placeholder, will be calculated
        let checksum_pos = packet.len();
        packet.extend_from_slice(&[0, 0]);
        
        // Urgent pointer (2 bytes)
        packet.extend_from_slice(&tcp.urgent_pointer.to_be_bytes());
        
        // Options
        packet.extend_from_slice(&tcp.options);
        
        // Payload
        packet.extend_from_slice(&tcp.payload);

        // Calculate and insert checksum
        let checksum = Self::calculate_tcp_checksum(&packet, source_ip, dest_ip)?;
        packet[checksum_pos] = (checksum >> 8) as u8;
        packet[checksum_pos + 1] = (checksum & 0xFF) as u8;

        debug!(
            "Built TCP packet: {}:{} -> {}:{}, flags={:?}, {} bytes",
            source_ip, tcp.source_port, dest_ip, tcp.dest_port,
            tcp.flags, packet.len()
        );

        Ok(packet)
    }

    /// Build a UDP packet
    pub fn build_udp(&self, udp: &UdpPacket) -> ScanResult<Vec<u8>> {
        trace!("Building UDP packet: {:?}", udp);

        let dest_ip = self.dest_ip.ok_or_else(|| {
            ScanError::packet_error("Destination IP not set")
        })?;

        let source_ip = self.source_ip.unwrap_or_else(|| {
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
        });

        // Create UDP header (8 bytes)
        let mut packet = Vec::with_capacity(8 + udp.payload.len());

        // Source port (2 bytes)
        packet.extend_from_slice(&udp.source_port.to_be_bytes());
        
        // Destination port (2 bytes)
        packet.extend_from_slice(&udp.dest_port.to_be_bytes());
        
        // Length (2 bytes)
        let length = (8 + udp.payload.len()) as u16;
        packet.extend_from_slice(&length.to_be_bytes());
        
        // Checksum (2 bytes) - placeholder
        let checksum_pos = packet.len();
        packet.extend_from_slice(&[0, 0]);
        
        // Payload
        packet.extend_from_slice(&udp.payload);

        // Calculate and insert checksum
        let checksum = Self::calculate_udp_checksum(&packet, source_ip, dest_ip)?;
        packet[checksum_pos] = (checksum >> 8) as u8;
        packet[checksum_pos + 1] = (checksum & 0xFF) as u8;

        debug!(
            "Built UDP packet: {}:{} -> {}:{}, {} bytes",
            source_ip, udp.source_port, dest_ip, udp.dest_port, packet.len()
        );

        Ok(packet)
    }

    /// Build an ICMP packet
    pub fn build_icmp(&self, icmp: &IcmpPacket) -> ScanResult<Vec<u8>> {
        trace!("Building ICMP packet: {:?}", icmp);

        // Create ICMP header (8 bytes minimum)
        let mut packet = Vec::with_capacity(8 + icmp.payload.len());

        // Type (1 byte)
        packet.push(icmp.icmp_type);
        
        // Code (1 byte)
        packet.push(icmp.code);
        
        // Checksum (2 bytes) - placeholder
        let checksum_pos = packet.len();
        packet.extend_from_slice(&[0, 0]);
        
        // Identifier (2 bytes)
        packet.extend_from_slice(&icmp.identifier.to_be_bytes());
        
        // Sequence (2 bytes)
        packet.extend_from_slice(&icmp.sequence.to_be_bytes());
        
        // Payload
        packet.extend_from_slice(&icmp.payload);

        // Calculate and insert checksum
        let checksum = Self::calculate_icmp_checksum(&packet);
        packet[checksum_pos] = (checksum >> 8) as u8;
        packet[checksum_pos + 1] = (checksum & 0xFF) as u8;

        debug!(
            "Built ICMP packet: type={}, code={}, id={}, seq={}, {} bytes",
            icmp.icmp_type, icmp.code, icmp.identifier, icmp.sequence, packet.len()
        );

        Ok(packet)
    }

    /// Calculate TCP checksum
    fn calculate_tcp_checksum(
        packet: &[u8],
        source_ip: IpAddr,
        dest_ip: IpAddr,
    ) -> ScanResult<u16> {
        // TCP checksum includes a pseudo-header
        let mut sum: u32 = 0;

        // Add pseudo-header
        match (source_ip, dest_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                for byte in src.octets().chunks(2) {
                    sum += u16::from_be_bytes([byte[0], byte[1]]) as u32;
                }
                for byte in dst.octets().chunks(2) {
                    sum += u16::from_be_bytes([byte[0], byte[1]]) as u32;
                }
                sum += 6u32; // TCP protocol number
                sum += packet.len() as u32;
            }
            _ => {
                return Err(ScanError::packet_error("IPv6 checksum not yet implemented"));
            }
        }

        // Add packet data
        for chunk in packet.chunks(2) {
            if chunk.len() == 2 {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            } else {
                sum += (chunk[0] as u32) << 8;
            }
        }

        // Fold 32-bit sum to 16 bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        Ok(!sum as u16)
    }

    /// Calculate UDP checksum
    fn calculate_udp_checksum(
        packet: &[u8],
        source_ip: IpAddr,
        dest_ip: IpAddr,
    ) -> ScanResult<u16> {
        // UDP checksum is calculated the same way as TCP
        Self::calculate_tcp_checksum(packet, source_ip, dest_ip)
    }

    /// Calculate ICMP checksum
    fn calculate_icmp_checksum(packet: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        for chunk in packet.chunks(2) {
            if chunk.len() == 2 {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            } else {
                sum += (chunk[0] as u32) << 8;
            }
        }

        // Fold 32-bit sum to 16 bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }
}

impl Default for PacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags() {
        let syn = TcpFlags::syn();
        assert!(syn.syn);
        assert!(!syn.ack);

        let syn_ack = TcpFlags::syn_ack();
        assert!(syn_ack.syn);
        assert!(syn_ack.ack);

        let flags_byte = syn.to_u8();
        assert_eq!(flags_byte, 0x02);

        let parsed = TcpFlags::from_u8(0x12);
        assert!(parsed.syn);
        assert!(parsed.ack);
    }

    #[test]
    fn test_icmp_echo_request() {
        let icmp = IcmpPacket::echo_request(1234, 1);
        assert_eq!(icmp.icmp_type, 8);
        assert_eq!(icmp.code, 0);
        assert_eq!(icmp.identifier, 1234);
        assert_eq!(icmp.sequence, 1);
    }

    #[test]
    fn test_packet_builder_creation() {
        let builder = PacketBuilder::new();
        assert_eq!(builder.ttl, 64);
        assert!(builder.source_ip.is_none());
    }

    #[test]
    fn test_packet_builder_chain() {
        let source = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dest = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        let builder = PacketBuilder::new()
            .source(source)
            .destination(dest)
            .ttl(128);

        assert_eq!(builder.ttl, 128);
        assert_eq!(builder.source_ip, Some(source));
        assert_eq!(builder.dest_ip, Some(dest));
    }

    #[test]
    fn test_build_icmp_packet() {
        let builder = PacketBuilder::new();
        let icmp = IcmpPacket::echo_request(1, 1);
        
        let packet = builder.build_icmp(&icmp);
        assert!(packet.is_ok());
        
        let packet = packet.unwrap();
        assert!(packet.len() >= 8); // Minimum ICMP header size
        assert_eq!(packet[0], 8);   // Echo request type
        assert_eq!(packet[1], 0);   // Code
    }

    #[test]
    fn test_build_tcp_packet() {
        let source = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dest = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        let builder = PacketBuilder::new()
            .source(source)
            .destination(dest);

        let tcp = TcpPacket {
            source_port: 12345,
            dest_port: 80,
            sequence: 1000,
            acknowledgment: 0,
            flags: TcpFlags::syn(),
            window: 65535,
            urgent_pointer: 0,
            options: vec![],
            payload: vec![],
        };

        let packet = builder.build_tcp(&tcp);
        assert!(packet.is_ok());
        
        let packet = packet.unwrap();
        assert!(packet.len() >= 20); // Minimum TCP header size
    }

    #[test]
    fn test_build_udp_packet() {
        let source = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dest = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        let builder = PacketBuilder::new()
            .source(source)
            .destination(dest);

        let udp = UdpPacket {
            source_port: 12345,
            dest_port: 53,
            payload: vec![1, 2, 3, 4],
        };

        let packet = builder.build_udp(&udp);
        assert!(packet.is_ok());
        
        let packet = packet.unwrap();
        assert_eq!(packet.len(), 12); // 8 byte header + 4 byte payload
    }
}

