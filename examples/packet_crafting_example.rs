/// Packet crafting example
/// 
/// This example demonstrates packet crafting capabilities for TCP, UDP, and ICMP.

use nrmap::packet::{PacketBuilder, TcpPacket, UdpPacket, IcmpPacket};
use nrmap::packet::crafting::TcpFlags;
use std::net::{IpAddr, Ipv4Addr};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("NrMAP Packet Crafting Example\n");

    let source = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let dest = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

    // Example 1: Craft a TCP SYN packet
    println!("Example 1: TCP SYN Packet");
    println!("{}", "-".repeat(50));
    
    let builder = PacketBuilder::new()
        .source(source)
        .destination(dest)
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
            println!("TCP SYN packet crafted successfully");
            println!("  Source: {}:{}", source, tcp_syn.source_port);
            println!("  Destination: {}:{}", dest, tcp_syn.dest_port);
            println!("  Flags: SYN");
            println!("  Packet size: {} bytes", packet.len());
            println!("  First 20 bytes: {:02x?}", &packet[..20.min(packet.len())]);
        }
        Err(e) => {
            println!("Error crafting TCP packet: {}", e);
        }
    }
    
    println!();

    // Example 2: Craft a UDP packet
    println!("Example 2: UDP Packet");
    println!("{}", "-".repeat(50));
    
    let builder = PacketBuilder::new()
        .source(source)
        .destination(dest);

    let udp = UdpPacket {
        source_port: 12345,
        dest_port: 53,
        payload: vec![0x12, 0x34, 0x01, 0x00], // DNS query header
    };

    match builder.build_udp(&udp) {
        Ok(packet) => {
            println!("UDP packet crafted successfully");
            println!("  Source: {}:{}", source, udp.source_port);
            println!("  Destination: {}:{}", dest, udp.dest_port);
            println!("  Payload size: {} bytes", udp.payload.len());
            println!("  Packet size: {} bytes", packet.len());
        }
        Err(e) => {
            println!("Error crafting UDP packet: {}", e);
        }
    }
    
    println!();

    // Example 3: Craft an ICMP Echo Request (ping)
    println!("Example 3: ICMP Echo Request");
    println!("{}", "-".repeat(50));
    
    let builder = PacketBuilder::new();
    let icmp = IcmpPacket::echo_request(1234, 1);

    match builder.build_icmp(&icmp) {
        Ok(packet) => {
            println!("ICMP Echo Request crafted successfully");
            println!("  Type: Echo Request (8)");
            println!("  Code: 0");
            println!("  Identifier: {}", icmp.identifier);
            println!("  Sequence: {}", icmp.sequence);
            println!("  Packet size: {} bytes", packet.len());
        }
        Err(e) => {
            println!("Error crafting ICMP packet: {}", e);
        }
    }
    
    println!();

    // Example 4: Craft TCP with options
    println!("Example 4: TCP with Options");
    println!("{}", "-".repeat(50));
    
    let builder = PacketBuilder::new()
        .source(source)
        .destination(dest);

    // MSS option: kind=2, length=4, value=1460
    let mss_option = vec![2, 4, 0x05, 0xb4];
    
    let tcp_with_options = TcpPacket {
        source_port: 55555,
        dest_port: 443,
        sequence: 2000,
        acknowledgment: 0,
        flags: TcpFlags::syn(),
        window: 29200,
        urgent_pointer: 0,
        options: mss_option,
        payload: vec![],
    };

    match builder.build_tcp(&tcp_with_options) {
        Ok(packet) => {
            println!("TCP packet with options crafted successfully");
            println!("  Options included: MSS");
            println!("  Packet size: {} bytes", packet.len());
        }
        Err(e) => {
            println!("Error crafting TCP packet: {}", e);
        }
    }

    println!("\nExample completed!");
    println!("\nNote: Sending these packets requires raw socket privileges.");
    println!("Use the packet engine's RawSocket for actual transmission.");

    Ok(())
}

