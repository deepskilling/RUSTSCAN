/// Packet parser module using pnet for analyzing network packets
/// 
/// Provides parsing capabilities for TCP, UDP, ICMP, and IP packets
/// with validation and field extraction using the pnet library.

use crate::error::{ScanError, ScanResult};
use crate::packet::crafting::TcpFlags;
use pnet::packet::Packet;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket as PnetTcpPacket;
use pnet::packet::tcp::TcpOption;
use pnet::packet::udp::UdpPacket as PnetUdpPacket;
use pnet::packet::icmp::IcmpPacket as PnetIcmpPacket;
use pnet::packet::icmp::echo_request::EchoRequestPacket;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use std::net::IpAddr;
use tracing::{debug, trace, warn};

/// Type of parsed packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Igmp,
    Other(u8),
}

/// Parsed packet information
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub packet_type: PacketType,
    pub source_ip: IpAddr,
    pub dest_ip: IpAddr,
    pub ttl: u8,
    pub protocol: u8,
    pub payload: Vec<u8>,
    pub tcp_info: Option<ParsedTcpPacket>,
    pub udp_info: Option<ParsedUdpPacket>,
    pub icmp_info: Option<ParsedIcmpPacket>,
}

/// Parsed TCP packet
#[derive(Debug, Clone)]
pub struct ParsedTcpPacket {
    pub source_port: u16,
    pub dest_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub data_offset: u8,
    pub options: Vec<TcpOption>,
}

/// Parsed UDP packet
#[derive(Debug, Clone)]
pub struct ParsedUdpPacket {
    pub source_port: u16,
    pub dest_port: u16,
    pub length: u16,
    pub checksum: u16,
}

/// Parsed ICMP packet
#[derive(Debug, Clone)]
pub struct ParsedIcmpPacket {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub identifier: Option<u16>,
    pub sequence: Option<u16>,
    pub rest_of_header: Option<u32>, // For other ICMP types
}

/// Packet parser using pnet
pub struct PacketParser {
    validate_checksums: bool,
}

impl PacketParser {
    /// Create a new packet parser
    /// 
    /// # Arguments
    /// * `validate_checksums` - Whether to validate packet checksums
    pub fn new(validate_checksums: bool) -> Self {
        debug!("Creating pnet-based packet parser (validate_checksums={})", validate_checksums);
        Self { validate_checksums }
    }

    /// Parse a raw packet
    /// 
    /// # Arguments
    /// * `data` - Raw packet bytes
    /// 
    /// # Returns
    /// * `ScanResult<ParsedPacket>` - Parsed packet information
    pub fn parse(&self, data: &[u8]) -> ScanResult<ParsedPacket> {
        trace!("Parsing packet of {} bytes with pnet", data.len());

        if data.len() < 20 {
            return Err(ScanError::packet_error("Packet too small to be valid IP"));
        }

        // Check IP version
        let version = (data[0] >> 4) & 0x0F;

        match version {
            4 => self.parse_ipv4(data),
            6 => self.parse_ipv6(data),
            _ => Err(ScanError::packet_error(format!(
                "Unknown IP version: {}",
                version
            ))),
        }
    }

    /// Parse an IPv4 packet using pnet
    fn parse_ipv4(&self, data: &[u8]) -> ScanResult<ParsedPacket> {
        let ip_packet = Ipv4Packet::new(data)
            .ok_or_else(|| ScanError::packet_error("Failed to parse IPv4 packet"))?;

        // Validate checksum if requested
        if self.validate_checksums {
            let calculated_checksum = pnet::packet::ipv4::checksum(&ip_packet);
            if calculated_checksum != ip_packet.get_checksum() && ip_packet.get_checksum() != 0 {
                warn!(
                    "IPv4 checksum mismatch: expected {}, got {}",
                    ip_packet.get_checksum(), calculated_checksum
                );
            }
        }

        let source_ip = IpAddr::V4(ip_packet.get_source());
        let dest_ip = IpAddr::V4(ip_packet.get_destination());
        let ttl = ip_packet.get_ttl();
        let protocol = ip_packet.get_next_level_protocol().0;

        debug!(
            "Parsed IPv4: {} -> {}, protocol={}, ttl={}",
            source_ip, dest_ip, protocol, ttl
        );

        // Parse transport layer
        let transport_data = ip_packet.payload();
        let (packet_type, tcp_info, udp_info, icmp_info, payload) =
            self.parse_transport_layer(protocol, transport_data, source_ip, dest_ip)?;

        Ok(ParsedPacket {
            packet_type,
            source_ip,
            dest_ip,
            ttl,
            protocol,
            payload,
            tcp_info,
            udp_info,
            icmp_info,
        })
    }

    /// Parse an IPv6 packet using pnet
    fn parse_ipv6(&self, data: &[u8]) -> ScanResult<ParsedPacket> {
        let ip_packet = Ipv6Packet::new(data)
            .ok_or_else(|| ScanError::packet_error("Failed to parse IPv6 packet"))?;

        let source_ip = IpAddr::V6(ip_packet.get_source());
        let dest_ip = IpAddr::V6(ip_packet.get_destination());
        let ttl = ip_packet.get_hop_limit();
        let protocol = ip_packet.get_next_header().0;

        debug!(
            "Parsed IPv6: {} -> {}, protocol={}, hop_limit={}",
            source_ip, dest_ip, protocol, ttl
        );

        // Parse transport layer
        let transport_data = ip_packet.payload();
        let (packet_type, tcp_info, udp_info, icmp_info, payload) =
            self.parse_transport_layer(protocol, transport_data, source_ip, dest_ip)?;

        Ok(ParsedPacket {
            packet_type,
            source_ip,
            dest_ip,
            ttl,
            protocol,
            payload,
            tcp_info,
            udp_info,
            icmp_info,
        })
    }

    /// Parse transport layer (TCP/UDP/ICMP) using pnet
    fn parse_transport_layer(
        &self,
        protocol: u8,
        data: &[u8],
        source_ip: IpAddr,
        dest_ip: IpAddr,
    ) -> ScanResult<(
        PacketType,
        Option<ParsedTcpPacket>,
        Option<ParsedUdpPacket>,
        Option<ParsedIcmpPacket>,
        Vec<u8>,
    )> {
        match protocol {
            6 => {
                // TCP
                let tcp_info = self.parse_tcp(data, source_ip, dest_ip)?;
                let payload_offset = tcp_info.data_offset as usize * 4;
                let payload = if payload_offset < data.len() {
                    data[payload_offset..].to_vec()
                } else {
                    vec![]
                };
                Ok((PacketType::Tcp, Some(tcp_info), None, None, payload))
            }
            17 => {
                // UDP
                let udp_info = self.parse_udp(data, source_ip, dest_ip)?;
                let payload = if data.len() > 8 {
                    data[8..].to_vec()
                } else {
                    vec![]
                };
                Ok((PacketType::Udp, None, Some(udp_info), None, payload))
            }
            1 => {
                // ICMP (IPv4)
                let icmp_info = self.parse_icmp(data)?;
                let payload = if data.len() > 8 {
                    data[8..].to_vec()
                } else {
                    vec![]
                };
                Ok((PacketType::Icmp, None, None, Some(icmp_info), payload))
            }
            58 => {
                // ICMPv6
                let icmp_info = self.parse_icmp(data)?;
                let payload = if data.len() > 8 {
                    data[8..].to_vec()
                } else {
                    vec![]
                };
                Ok((PacketType::Icmpv6, None, None, Some(icmp_info), payload))
            }
            2 => {
                // IGMP
                Ok((PacketType::Igmp, None, None, None, data.to_vec()))
            }
            _ => {
                Ok((PacketType::Other(protocol), None, None, None, data.to_vec()))
            }
        }
    }

    /// Parse TCP packet using pnet
    fn parse_tcp(&self, data: &[u8], source_ip: IpAddr, dest_ip: IpAddr) -> ScanResult<ParsedTcpPacket> {
        let tcp_packet = PnetTcpPacket::new(data)
            .ok_or_else(|| ScanError::packet_error("Failed to parse TCP packet"))?;

        // Validate checksum if requested
        if self.validate_checksums {
            let calculated_checksum = match (source_ip, dest_ip) {
                (IpAddr::V4(src), IpAddr::V4(dst)) => {
                    pnet::packet::tcp::ipv4_checksum(&tcp_packet, &src, &dst)
                }
                (IpAddr::V6(src), IpAddr::V6(dst)) => {
                    pnet::packet::tcp::ipv6_checksum(&tcp_packet, &src, &dst)
                }
                _ => {
                    warn!("TCP checksum validation skipped: IP version mismatch");
                    tcp_packet.get_checksum()
                }
            };

            if calculated_checksum != tcp_packet.get_checksum() && tcp_packet.get_checksum() != 0 {
                warn!(
                    "TCP checksum mismatch: expected {}, got {}",
                    tcp_packet.get_checksum(), calculated_checksum
                );
            }
        }

        let flags = TcpFlags::from_u8(tcp_packet.get_flags());
        // For now, we'll skip parsing TCP options due to pnet API complexities
        // In production, you'd need to manually extract and construct TcpOptions
        let options: Vec<TcpOption> = vec![];

        debug!(
            "Parsed TCP: {}:{} -> {}:{}, seq={}, ack={}, flags={:?}",
            source_ip, tcp_packet.get_source(), 
            dest_ip, tcp_packet.get_destination(),
            tcp_packet.get_sequence(), tcp_packet.get_acknowledgement(), flags
        );

        Ok(ParsedTcpPacket {
            source_port: tcp_packet.get_source(),
            dest_port: tcp_packet.get_destination(),
            sequence: tcp_packet.get_sequence(),
            acknowledgment: tcp_packet.get_acknowledgement(),
            flags,
            window: tcp_packet.get_window(),
            checksum: tcp_packet.get_checksum(),
            urgent_pointer: tcp_packet.get_urgent_ptr(),
            data_offset: tcp_packet.get_data_offset(),
            options,
        })
    }

    /// Parse UDP packet using pnet
    fn parse_udp(&self, data: &[u8], source_ip: IpAddr, dest_ip: IpAddr) -> ScanResult<ParsedUdpPacket> {
        let udp_packet = PnetUdpPacket::new(data)
            .ok_or_else(|| ScanError::packet_error("Failed to parse UDP packet"))?;

        // Validate checksum if requested
        if self.validate_checksums && udp_packet.get_checksum() != 0 {
            let calculated_checksum = match (source_ip, dest_ip) {
                (IpAddr::V4(src), IpAddr::V4(dst)) => {
                    pnet::packet::udp::ipv4_checksum(&udp_packet, &src, &dst)
                }
                (IpAddr::V6(src), IpAddr::V6(dst)) => {
                    pnet::packet::udp::ipv6_checksum(&udp_packet, &src, &dst)
                }
                _ => {
                    warn!("UDP checksum validation skipped: IP version mismatch");
                    udp_packet.get_checksum()
                }
            };

            if calculated_checksum != udp_packet.get_checksum() {
                warn!(
                    "UDP checksum mismatch: expected {}, got {}",
                    udp_packet.get_checksum(), calculated_checksum
                );
            }
        }

        debug!(
            "Parsed UDP: {}:{} -> {}:{}, length={}",
            source_ip, udp_packet.get_source(),
            dest_ip, udp_packet.get_destination(),
            udp_packet.get_length()
        );

        Ok(ParsedUdpPacket {
            source_port: udp_packet.get_source(),
            dest_port: udp_packet.get_destination(),
            length: udp_packet.get_length(),
            checksum: udp_packet.get_checksum(),
        })
    }

    /// Parse ICMP packet using pnet
    fn parse_icmp(&self, data: &[u8]) -> ScanResult<ParsedIcmpPacket> {
        let icmp_packet = PnetIcmpPacket::new(data)
            .ok_or_else(|| ScanError::packet_error("Failed to parse ICMP packet"))?;

        // Validate checksum if requested
        if self.validate_checksums {
            let calculated_checksum = pnet::packet::icmp::checksum(&icmp_packet);
            if calculated_checksum != icmp_packet.get_checksum() && icmp_packet.get_checksum() != 0 {
                warn!(
                    "ICMP checksum mismatch: expected {}, got {}",
                    icmp_packet.get_checksum(), calculated_checksum
                );
            }
        }

        let icmp_type = icmp_packet.get_icmp_type().0;
        let code = icmp_packet.get_icmp_code().0;
        let checksum = icmp_packet.get_checksum();

        // For Echo Request/Reply, parse identifier and sequence
        let (identifier, sequence) = if icmp_type == 0 || icmp_type == 8 {
            // Try Echo Reply first
            if let Some(echo_reply) = EchoReplyPacket::new(data) {
                (Some(echo_reply.get_identifier()), Some(echo_reply.get_sequence_number()))
            }
            // Try Echo Request
            else if let Some(echo_request) = EchoRequestPacket::new(data) {
                (Some(echo_request.get_identifier()), Some(echo_request.get_sequence_number()))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        // Extract rest_of_header for other ICMP types (4 bytes after type/code/checksum)
        let rest_of_header = if data.len() >= 8 && identifier.is_none() {
            Some(u32::from_be_bytes([data[4], data[5], data[6], data[7]]))
        } else {
            None
        };

        debug!(
            "Parsed ICMP: type={}, code={}, id={:?}, seq={:?}",
            icmp_type, code, identifier, sequence
        );

        Ok(ParsedIcmpPacket {
            icmp_type,
            code,
            checksum,
            identifier,
            sequence,
            rest_of_header,
        })
    }
}

impl Default for PacketParser {
    fn default() -> Self {
        Self::new(true)
    }
}

impl std::fmt::Display for PacketType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketType::Tcp => write!(f, "TCP"),
            PacketType::Udp => write!(f, "UDP"),
            PacketType::Icmp => write!(f, "ICMP"),
            PacketType::Icmpv6 => write!(f, "ICMPv6"),
            PacketType::Igmp => write!(f, "IGMP"),
            PacketType::Other(proto) => write!(f, "Protocol {}", proto),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_creation() {
        let parser = PacketParser::new(true);
        assert!(parser.validate_checksums);

        let parser_no_validation = PacketParser::new(false);
        assert!(!parser_no_validation.validate_checksums);
    }

    #[test]
    fn test_packet_type_display() {
        assert_eq!(format!("{}", PacketType::Tcp), "TCP");
        assert_eq!(format!("{}", PacketType::Udp), "UDP");
        assert_eq!(format!("{}", PacketType::Icmp), "ICMP");
        assert_eq!(format!("{}", PacketType::Icmpv6), "ICMPv6");
        assert_eq!(format!("{}", PacketType::Other(89)), "Protocol 89");
    }

    #[test]
    fn test_parse_too_small() {
        let parser = PacketParser::new(true);
        let small_packet = vec![0u8; 10];
        
        let result = parser.parse(&small_packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_version() {
        let parser = PacketParser::new(false);
        let mut packet = vec![0u8; 20];
        packet[0] = 0x30; // Version 3 (invalid)
        
        let result = parser.parse(&packet);
        assert!(result.is_err());
    }
}
