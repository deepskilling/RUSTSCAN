/// Packet crafting example using pnet
/// 
/// This example demonstrates packet crafting capabilities for TCP, UDP, and ICMP
/// using the pnet library for production-quality packet handling.

use nrmap::packet::{PacketBuilder, TcpPacket, UdpPacket, IcmpPacket};
use nrmap::packet::crafting::TcpFlags;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("NrMAP Packet Crafting Example (pnet-based)\n");
    println!("This example demonstrates the new pnet-based packet crafting");
    println!("which provides IPv6 support, better checksums, and production-quality code.\n");

    let source_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let dest_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    
    let source_v6 = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    let dest_v6 = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));

    // Example 1: Craft a TCP SYN packet (IPv4)
    println!("Example 1: TCP SYN Packet (IPv4)");
    println!("{}", "-".repeat(50));
    
    let builder = PacketBuilder::new()
        .source(source_v4)
        .destination(dest_v4)
        .ttl(64);

    let tcp_syn = TcpPacket {
        source_port: 54321,
        dest_port: 80,
        sequence: 1000,
        acknowledgment: 0,
        flags: TcpFlags::syn(),
        window: 65535,
        urgent_pointer: 0,
        options: vec![],
        payload: vec![],
    };

    match builder.build_tcp(&tcp_syn) {
        Ok(packet) => {
            println!("✅ TCP SYN packet crafted successfully");
            println!("  Source: {}:{}", source_v4, tcp_syn.source_port);
            println!("  Destination: {}:{}", dest_v4, tcp_syn.dest_port);
            println!("  Flags: SYN");
            println!("  Packet size: {} bytes (includes IP header)", packet.len());
            println!("  IP header: {} bytes", if source_v4.is_ipv4() { 20 } else { 40 });
            println!("  First 20 bytes: {:02x?}", &packet[..20.min(packet.len())]);
        }
        Err(e) => {
            println!("❌ Error crafting TCP packet: {}", e);
        }
    }
    
    println!();

    // Example 2: Craft a TCP SYN packet (IPv6)
    println!("Example 2: TCP SYN Packet (IPv6)");
    println!("{}", "-".repeat(50));
    
    let builder_v6 = PacketBuilder::new()
        .source(source_v6)
        .destination(dest_v6)
        .ttl(64);

    let tcp_syn_v6 = TcpPacket {
        source_port: 54321,
        dest_port: 80,
        sequence: 1000,
        acknowledgment: 0,
        flags: TcpFlags::syn(),
        window: 65535,
        urgent_pointer: 0,
        options: vec![],
        payload: vec![],
    };

    match builder_v6.build_tcp(&tcp_syn_v6) {
        Ok(packet) => {
            println!("✅ TCP SYN packet (IPv6) crafted successfully");
            println!("  Source: {}:{}", source_v6, tcp_syn_v6.source_port);
            println!("  Destination: {}:{}", dest_v6, tcp_syn_v6.dest_port);
            println!("  Flags: SYN");
            println!("  Packet size: {} bytes (includes IPv6 header)", packet.len());
            println!("  IPv6 header: 40 bytes");
        }
        Err(e) => {
            println!("❌ Error crafting TCP packet: {}", e);
        }
    }
    
    println!();

    // Example 3: Craft a UDP packet (IPv4)
    println!("Example 3: UDP Packet (IPv4)");
    println!("{}", "-".repeat(50));
    
    let builder = PacketBuilder::new()
        .source(source_v4)
        .destination(dest_v4);

    let udp = UdpPacket {
        source_port: 12345,
        dest_port: 53,
        payload: vec![0x12, 0x34, 0x01, 0x00], // DNS query header
    };

    match builder.build_udp(&udp) {
        Ok(packet) => {
            println!("✅ UDP packet crafted successfully");
            println!("  Source: {}:{}", source_v4, udp.source_port);
            println!("  Destination: {}:{}", dest_v4, udp.dest_port);
            println!("  Payload size: {} bytes", udp.payload.len());
            println!("  Packet size: {} bytes (includes IP + UDP headers)", packet.len());
        }
        Err(e) => {
            println!("❌ Error crafting UDP packet: {}", e);
        }
    }
    
    println!();

    // Example 4: Craft a UDP packet (IPv6)
    println!("Example 4: UDP Packet (IPv6)");
    println!("{}", "-".repeat(50));
    
    let builder_v6 = PacketBuilder::new()
        .source(source_v6)
        .destination(dest_v6);

    let udp_v6 = UdpPacket {
        source_port: 12345,
        dest_port: 53,
        payload: vec![0x12, 0x34, 0x01, 0x00],
    };

    match builder_v6.build_udp(&udp_v6) {
        Ok(packet) => {
            println!("✅ UDP packet (IPv6) crafted successfully");
            println!("  Source: {}:{}", source_v6, udp_v6.source_port);
            println!("  Destination: {}:{}", dest_v6, udp_v6.dest_port);
            println!("  Payload size: {} bytes", udp_v6.payload.len());
            println!("  Packet size: {} bytes (includes IPv6 + UDP headers)", packet.len());
        }
        Err(e) => {
            println!("❌ Error crafting UDP packet: {}", e);
        }
    }
    
    println!();

    // Example 5: Craft an ICMP Echo Request (ping)
    println!("Example 5: ICMP Echo Request");
    println!("{}", "-".repeat(50));
    
    let builder = PacketBuilder::new();
    let icmp = IcmpPacket::echo_request(1234, 1);

    match builder.build_icmp(&icmp) {
        Ok(packet) => {
            println!("✅ ICMP Echo Request crafted successfully");
            println!("  Type: Echo Request (8)");
            println!("  Code: 0");
            println!("  Identifier: {}", icmp.identifier);
            println!("  Sequence: {}", icmp.sequence);
            println!("  Packet size: {} bytes", packet.len());
        }
        Err(e) => {
            println!("❌ Error crafting ICMP packet: {}", e);
        }
    }
    
    println!();

    // Example 6: Craft ICMP Timestamp Request
    println!("Example 6: ICMP Timestamp Request");
    println!("{}", "-".repeat(50));
    
    let builder = PacketBuilder::new();
    let icmp_ts = IcmpPacket::timestamp_request(1234, 1);

    match builder.build_icmp(&icmp_ts) {
        Ok(packet) => {
            println!("✅ ICMP Timestamp Request crafted successfully");
            println!("  Type: Timestamp Request (13)");
            println!("  Code: 0");
            println!("  Identifier: {}", icmp_ts.identifier);
            println!("  Sequence: {}", icmp_ts.sequence);
            println!("  Packet size: {} bytes", packet.len());
        }
        Err(e) => {
            println!("❌ Error crafting ICMP packet: {}", e);
        }
    }
    
    println!();

    // Example 7: Craft TCP with complex flags
    println!("Example 7: TCP with Multiple Flags");
    println!("{}", "-".repeat(50));
    
    let builder = PacketBuilder::new()
        .source(source_v4)
        .destination(dest_v4);

    let tcp_flags = TcpFlags {
        syn: true,
        ack: true,
        ece: true,
        ..Default::default()
    };
    
    let tcp_complex = TcpPacket {
        source_port: 55555,
        dest_port: 443,
        sequence: 2000,
        acknowledgment: 1500,
        flags: tcp_flags,
        window: 29200,
        urgent_pointer: 0,
        options: vec![],
        payload: vec![],
    };

    match builder.build_tcp(&tcp_complex) {
        Ok(packet) => {
            println!("✅ TCP packet with complex flags crafted successfully");
            println!("  Flags: SYN+ACK+ECE");
            println!("  Packet size: {} bytes", packet.len());
        }
        Err(e) => {
            println!("❌ Error crafting TCP packet: {}", e);
        }
    }

    println!("\n{}", "=".repeat(50));
    println!("✅ Example completed successfully!");
    println!("{}", "=".repeat(50));
    println!("\n📝 Key improvements with pnet:");
    println!("  • Full IPv6 support (previously unsupported)");
    println!("  • Automatic checksum calculation (more reliable)");
    println!("  • Production-tested packet structures");
    println!("  • Zero-copy packet parsing");
    println!("  • Better error handling");
    println!("\n⚠️  Note: Sending these packets requires raw socket privileges.");
    println!("   Use the packet engine's RawSocket for actual transmission.");

    Ok(())
}
