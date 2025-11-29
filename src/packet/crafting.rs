/// Packet crafting module using pnet for creating network packets
/// 
/// Provides builders and utilities for crafting TCP, UDP, ICMP, and IP packets
/// with proper checksums and header fields using the pnet library.

use crate::error::{ScanError, ScanResult};
use pnet::packet::tcp::{MutableTcpPacket, TcpOption};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::icmp::{IcmpPacket as PnetIcmpPacket, MutableIcmpPacket};
use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Flags};
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
    pub options: Vec<TcpOption>,
    pub payload: Vec<u8>,
}

/// TCP flags - compatible with existing code but internally uses pnet
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
    pub ns: bool,
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

    /// Create flags for a FIN packet
    pub fn fin() -> Self {
        Self {
            fin: true,
            ..Default::default()
        }
    }

    /// Convert flags to u16 value (pnet format with NS bit)
    pub fn to_u16(&self) -> u16 {
        let mut flags = 0u16;
        if self.ns  { flags |= 0x100; }
        if self.cwr { flags |= 0x80; }
        if self.ece { flags |= 0x40; }
        if self.urg { flags |= 0x20; }
        if self.ack { flags |= 0x10; }
        if self.psh { flags |= 0x08; }
        if self.rst { flags |= 0x04; }
        if self.syn { flags |= 0x02; }
        if self.fin { flags |= 0x01; }
        flags
    }

    /// Convert flags to u8 value (legacy format)
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

    /// Parse flags from u16 value (pnet format)
    pub fn from_u16(flags: u16) -> Self {
        Self {
            ns:  (flags & 0x100) != 0,
            cwr: (flags & 0x80) != 0,
            ece: (flags & 0x40) != 0,
            urg: (flags & 0x20) != 0,
            ack: (flags & 0x10) != 0,
            psh: (flags & 0x08) != 0,
            rst: (flags & 0x04) != 0,
            syn: (flags & 0x02) != 0,
            fin: (flags & 0x01) != 0,
        }
    }

    /// Parse flags from u8 value (legacy format)
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
            ns: false,
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

    /// Create an ICMP Timestamp Request
    pub fn timestamp_request(identifier: u16, sequence: u16) -> Self {
        Self {
            icmp_type: 13,  // Timestamp Request
            code: 0,
            identifier,
            sequence,
            payload: vec![0; 12],  // Originate, Receive, Transmit timestamps
        }
    }
}

/// Packet builder for constructing network packets using pnet
pub struct PacketBuilder {
    source_ip: Option<IpAddr>,
    dest_ip: Option<IpAddr>,
    ttl: u8,
    identification: u16,
}

impl PacketBuilder {
    /// Create a new packet builder
    pub fn new() -> Self {
        debug!("Creating new pnet-based packet builder");
        Self {
            source_ip: None,
            dest_ip: None,
            ttl: 64,
            identification: rand::random(),
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

    /// Set IP identification field
    pub fn identification(mut self, id: u16) -> Self {
        self.identification = id;
        self
    }

    /// Build a complete TCP/IP packet
    pub fn build_tcp(&self, tcp: &TcpPacket) -> ScanResult<Vec<u8>> {
        trace!("Building TCP packet with pnet: {:?}", tcp);

        let dest_ip = self.dest_ip.ok_or_else(|| {
            ScanError::packet_error("Destination IP not set")
        })?;

        let source_ip = self.source_ip.ok_or_else(|| {
            ScanError::packet_error("Source IP not set")
        })?;

        match (source_ip, dest_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => self.build_tcp_ipv4(tcp, src, dst),
            (IpAddr::V6(src), IpAddr::V6(dst)) => self.build_tcp_ipv6(tcp, src, dst),
            _ => Err(ScanError::packet_error("Source and destination IP versions must match")),
        }
    }

    /// Build a TCP/IPv4 packet
    fn build_tcp_ipv4(&self, tcp: &TcpPacket, src: Ipv4Addr, dst: Ipv4Addr) -> ScanResult<Vec<u8>> {
        // Calculate sizes
        // For TCP options, we'll just use empty options for now
        // In production, serialize the options properly
        let tcp_options_len = 0; // Simplified: no options support yet
        let _ = &tcp.options; // Suppress unused warning
        let tcp_header_len = 20 + tcp_options_len;
        let tcp_total_len = tcp_header_len + tcp.payload.len();
        let ip_total_len = 20 + tcp_total_len;

        // Allocate buffer
        let mut buffer = vec![0u8; ip_total_len];

        // Build IP header
        {
            let mut ip_packet = MutableIpv4Packet::new(&mut buffer[..20])
                .ok_or_else(|| ScanError::packet_error("Failed to create IPv4 packet"))?;

            ip_packet.set_version(4);
            ip_packet.set_header_length(5); // 5 * 4 = 20 bytes
            ip_packet.set_dscp(0);
            ip_packet.set_ecn(0);
            ip_packet.set_total_length(ip_total_len as u16);
            ip_packet.set_identification(self.identification);
            ip_packet.set_flags(Ipv4Flags::DontFragment);
            ip_packet.set_fragment_offset(0);
            ip_packet.set_ttl(self.ttl);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip_packet.set_source(src);
            ip_packet.set_destination(dst);

            // Calculate and set IP checksum
            let checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
            ip_packet.set_checksum(checksum);
        }

        // Build TCP header
        {
            let mut tcp_packet = MutableTcpPacket::new(&mut buffer[20..])
                .ok_or_else(|| ScanError::packet_error("Failed to create TCP packet"))?;

            tcp_packet.set_source(tcp.source_port);
            tcp_packet.set_destination(tcp.dest_port);
            tcp_packet.set_sequence(tcp.sequence);
            tcp_packet.set_acknowledgement(tcp.acknowledgment);
            tcp_packet.set_data_offset((tcp_header_len / 4) as u8);
            tcp_packet.set_flags(tcp.flags.to_u8());
            tcp_packet.set_window(tcp.window);
            tcp_packet.set_urgent_ptr(tcp.urgent_pointer);

            // Note: TCP options support simplified for now
            // Options would require more complex serialization

            // Set payload
            if !tcp.payload.is_empty() {
                tcp_packet.set_payload(&tcp.payload);
            }

            // Calculate and set TCP checksum
            let checksum = pnet::packet::tcp::ipv4_checksum(
                &tcp_packet.to_immutable(),
                &src,
                &dst
            );
            tcp_packet.set_checksum(checksum);
        }

        debug!(
            "Built TCP/IPv4 packet: {}:{} -> {}:{}, flags={:?}, {} bytes",
            src, tcp.source_port, dst, tcp.dest_port,
            tcp.flags, buffer.len()
        );

        Ok(buffer)
    }

    /// Build a TCP/IPv6 packet
    fn build_tcp_ipv6(&self, tcp: &TcpPacket, src: Ipv6Addr, dst: Ipv6Addr) -> ScanResult<Vec<u8>> {
        // Calculate sizes
        let tcp_options_len = 0; // Simplified: no options support yet
        let _ = &tcp.options; // Suppress unused warning
        let tcp_header_len = 20 + tcp_options_len;
        let tcp_total_len = tcp_header_len + tcp.payload.len();
        let ip_total_len = 40 + tcp_total_len;

        // Allocate buffer
        let mut buffer = vec![0u8; ip_total_len];

        // Build IPv6 header
        {
            let mut ip_packet = MutableIpv6Packet::new(&mut buffer[..40])
                .ok_or_else(|| ScanError::packet_error("Failed to create IPv6 packet"))?;

            ip_packet.set_version(6);
            ip_packet.set_traffic_class(0);
            ip_packet.set_flow_label(0);
            ip_packet.set_payload_length(tcp_total_len as u16);
            ip_packet.set_next_header(IpNextHeaderProtocols::Tcp);
            ip_packet.set_hop_limit(self.ttl);
            ip_packet.set_source(src);
            ip_packet.set_destination(dst);
        }

        // Build TCP header
        {
            let mut tcp_packet = MutableTcpPacket::new(&mut buffer[40..])
                .ok_or_else(|| ScanError::packet_error("Failed to create TCP packet"))?;

            tcp_packet.set_source(tcp.source_port);
            tcp_packet.set_destination(tcp.dest_port);
            tcp_packet.set_sequence(tcp.sequence);
            tcp_packet.set_acknowledgement(tcp.acknowledgment);
            tcp_packet.set_data_offset((tcp_header_len / 4) as u8);
            tcp_packet.set_flags(tcp.flags.to_u8());
            tcp_packet.set_window(tcp.window);
            tcp_packet.set_urgent_ptr(tcp.urgent_pointer);

            // Note: TCP options support simplified for now
            // Options would require more complex serialization

            // Set payload
            if !tcp.payload.is_empty() {
                tcp_packet.set_payload(&tcp.payload);
            }

            // Calculate and set TCP checksum
            let checksum = pnet::packet::tcp::ipv6_checksum(
                &tcp_packet.to_immutable(),
                &src,
                &dst
            );
            tcp_packet.set_checksum(checksum);
        }

        debug!(
            "Built TCP/IPv6 packet: {}:{} -> {}:{}, flags={:?}, {} bytes",
            src, tcp.source_port, dst, tcp.dest_port,
            tcp.flags, buffer.len()
        );

        Ok(buffer)
    }

    /// Build a complete UDP/IP packet
    pub fn build_udp(&self, udp: &UdpPacket) -> ScanResult<Vec<u8>> {
        trace!("Building UDP packet with pnet: {:?}", udp);

        let dest_ip = self.dest_ip.ok_or_else(|| {
            ScanError::packet_error("Destination IP not set")
        })?;

        let source_ip = self.source_ip.ok_or_else(|| {
            ScanError::packet_error("Source IP not set")
        })?;

        match (source_ip, dest_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => self.build_udp_ipv4(udp, src, dst),
            (IpAddr::V6(src), IpAddr::V6(dst)) => self.build_udp_ipv6(udp, src, dst),
            _ => Err(ScanError::packet_error("Source and destination IP versions must match")),
        }
    }

    /// Build a UDP/IPv4 packet
    fn build_udp_ipv4(&self, udp: &UdpPacket, src: Ipv4Addr, dst: Ipv4Addr) -> ScanResult<Vec<u8>> {
        let udp_total_len = 8 + udp.payload.len();
        let ip_total_len = 20 + udp_total_len;

        let mut buffer = vec![0u8; ip_total_len];

        // Build IP header
        {
            let mut ip_packet = MutableIpv4Packet::new(&mut buffer[..20])
                .ok_or_else(|| ScanError::packet_error("Failed to create IPv4 packet"))?;

            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_total_length(ip_total_len as u16);
            ip_packet.set_identification(self.identification);
            ip_packet.set_flags(Ipv4Flags::DontFragment);
            ip_packet.set_ttl(self.ttl);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip_packet.set_source(src);
            ip_packet.set_destination(dst);

            let checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
            ip_packet.set_checksum(checksum);
        }

        // Build UDP header
        {
            let mut udp_packet = MutableUdpPacket::new(&mut buffer[20..])
                .ok_or_else(|| ScanError::packet_error("Failed to create UDP packet"))?;

            udp_packet.set_source(udp.source_port);
            udp_packet.set_destination(udp.dest_port);
            udp_packet.set_length(udp_total_len as u16);

            // Set payload
            if !udp.payload.is_empty() {
                udp_packet.set_payload(&udp.payload);
            }

            // Calculate and set UDP checksum
            let checksum = pnet::packet::udp::ipv4_checksum(
                &udp_packet.to_immutable(),
                &src,
                &dst
            );
            udp_packet.set_checksum(checksum);
        }

        debug!(
            "Built UDP/IPv4 packet: {}:{} -> {}:{}, {} bytes",
            src, udp.source_port, dst, udp.dest_port, buffer.len()
        );

        Ok(buffer)
    }

    /// Build a UDP/IPv6 packet
    fn build_udp_ipv6(&self, udp: &UdpPacket, src: Ipv6Addr, dst: Ipv6Addr) -> ScanResult<Vec<u8>> {
        let udp_total_len = 8 + udp.payload.len();
        let ip_total_len = 40 + udp_total_len;

        let mut buffer = vec![0u8; ip_total_len];

        // Build IPv6 header
        {
            let mut ip_packet = MutableIpv6Packet::new(&mut buffer[..40])
                .ok_or_else(|| ScanError::packet_error("Failed to create IPv6 packet"))?;

            ip_packet.set_version(6);
            ip_packet.set_payload_length(udp_total_len as u16);
            ip_packet.set_next_header(IpNextHeaderProtocols::Udp);
            ip_packet.set_hop_limit(self.ttl);
            ip_packet.set_source(src);
            ip_packet.set_destination(dst);
        }

        // Build UDP header
        {
            let mut udp_packet = MutableUdpPacket::new(&mut buffer[40..])
                .ok_or_else(|| ScanError::packet_error("Failed to create UDP packet"))?;

            udp_packet.set_source(udp.source_port);
            udp_packet.set_destination(udp.dest_port);
            udp_packet.set_length(udp_total_len as u16);

            // Set payload
            if !udp.payload.is_empty() {
                udp_packet.set_payload(&udp.payload);
            }

            // Calculate and set UDP checksum
            let checksum = pnet::packet::udp::ipv6_checksum(
                &udp_packet.to_immutable(),
                &src,
                &dst
            );
            udp_packet.set_checksum(checksum);
        }

        debug!(
            "Built UDP/IPv6 packet: {}:{} -> {}:{}, {} bytes",
            src, udp.source_port, dst, udp.dest_port, buffer.len()
        );

        Ok(buffer)
    }

    /// Build an ICMP packet (returns only ICMP payload, caller adds IP header)
    pub fn build_icmp(&self, icmp: &IcmpPacket) -> ScanResult<Vec<u8>> {
        trace!("Building ICMP packet with pnet: {:?}", icmp);

        // For Echo Request/Reply, use the specialized packet types
        if icmp.icmp_type == 8 || icmp.icmp_type == 0 {
            return self.build_icmp_echo(icmp);
        }

        // For other ICMP types, build generic ICMP packet
        let total_len = 8 + icmp.payload.len();
        let mut buffer = vec![0u8; total_len];

        let mut icmp_packet = MutableIcmpPacket::new(&mut buffer)
            .ok_or_else(|| ScanError::packet_error("Failed to create ICMP packet"))?;

        icmp_packet.set_icmp_type(pnet::packet::icmp::IcmpType(icmp.icmp_type));
        icmp_packet.set_icmp_code(pnet::packet::icmp::IcmpCode(icmp.code));

        // Set payload
        if !icmp.payload.is_empty() {
            icmp_packet.set_payload(&icmp.payload);
        }

        // Calculate and set checksum
        let checksum = pnet::packet::icmp::checksum(&icmp_packet.to_immutable());
        icmp_packet.set_checksum(checksum);

        debug!(
            "Built ICMP packet: type={}, code={}, {} bytes",
            icmp.icmp_type, icmp.code, buffer.len()
        );

        Ok(buffer)
    }

    /// Build an ICMP Echo Request/Reply packet
    fn build_icmp_echo(&self, icmp: &IcmpPacket) -> ScanResult<Vec<u8>> {
        let total_len = 8 + icmp.payload.len();
        let mut buffer = vec![0u8; total_len];

        // Manually build ICMP Echo packet due to pnet API complexities
        // Type (1 byte) - already set in buffer initialization
        buffer[0] = icmp.icmp_type;
        // Code (1 byte)
        buffer[1] = icmp.code;
        // Checksum (2 bytes) - placeholder, will calculate below
        // buffer[2..4] = 0x00
        // Identifier (2 bytes)
        buffer[4..6].copy_from_slice(&icmp.identifier.to_be_bytes());
        // Sequence (2 bytes)
        buffer[6..8].copy_from_slice(&icmp.sequence.to_be_bytes());
        // Payload
        if !icmp.payload.is_empty() {
            let payload_len = icmp.payload.len().min(buffer.len() - 8);
            buffer[8..8 + payload_len].copy_from_slice(&icmp.payload[..payload_len]);
        }

        // Calculate and set checksum
        let icmp_pkt = PnetIcmpPacket::new(&buffer)
            .ok_or_else(|| ScanError::packet_error("Failed to create ICMP packet for checksum"))?;
        let checksum = pnet::packet::icmp::checksum(&icmp_pkt);
        buffer[2..4].copy_from_slice(&checksum.to_be_bytes());

        debug!(
            "Built ICMP Echo packet: type={}, id={}, seq={}, {} bytes",
            icmp.icmp_type, icmp.identifier, icmp.sequence, buffer.len()
        );

        Ok(buffer)
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

        let flags_word = syn_ack.to_u16();
        let parsed_word = TcpFlags::from_u16(flags_word);
        assert_eq!(parsed_word, syn_ack);
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
    fn test_build_tcp_packet_ipv4() {
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
        assert!(packet.len() >= 40); // IP header (20) + TCP header (20)
    }

    #[test]
    fn test_build_tcp_packet_ipv6() {
        let source = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        let dest = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2));

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
        assert!(packet.len() >= 60); // IPv6 header (40) + TCP header (20)
    }

    #[test]
    fn test_build_udp_packet_ipv4() {
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
        assert_eq!(packet.len(), 32); // IP header (20) + UDP header (8) + payload (4)
    }

    #[test]
    fn test_build_udp_packet_ipv6() {
        let source = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        let dest = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2));

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
        assert_eq!(packet.len(), 52); // IPv6 header (40) + UDP header (8) + payload (4)
    }
}
