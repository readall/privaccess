

extern crate pnet;

use pnet::datalink::{self, Config, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet, MutablePacket};


use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

use pnet::util::MacAddr;

use std::str;
use std::time::{Duration, SystemTime};
use std::env;
use std::io::{self, Write};
use std::net::IpAddr;
use std::str::FromStr;
use std::process;
use std::process::Command;
// use std::serde;
use serde::{Serialize, Deserialize};

use sha2::Sha256;
use hmac::{Hmac, Mac, NewMac};

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

use aes::Aes128;
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use pbkdf2::pbkdf2;
use hex;
// create an alias for convenience
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

// create an alias for convenience
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

use std::collections::HashMap;

use config;
mod settings;
use settings::Settings;


static PRE_SHARED_KEY: &'static str = "6rHvrdTclgrRPOjclevU";
static PRE_SHARED_IV: &'static str =  "OGyfuckihucc0R02Xd6i";

struct MyConfig{
    pub sniff_port: u16,
    pub max_allowed_message_age_ms: u64
}

impl Default for MyConfig{
    fn default() -> MyConfig {
        MyConfig{
            sniff_port: 55055,
            max_allowed_message_age_ms: 5000
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct WireProtoMessage{
    client_id :String,
    enc_hmac_msg : Vec<u8>,
}


#[derive(Serialize, Deserialize, Debug)]
struct HmacProtoMessage{
    hmac_vec : Vec<u8>,
    message : Vec<u8>
}


#[derive(Serialize, Deserialize, Debug)]
struct ProtoMessage{
    // Identifier is expected to be an e-mail or similar
    identifier: String,

    // ports to which access is requested
    request_access_ports :Vec<u16>,

    // source IP address from where the request generated
    // if the client is behind a NAT or having dynamic IP address, 
    // it should first find out its public IP address and fill it here
    // could be v4 or v6 address
    source_ip_addr :IpAddr,
    
    // ip address whre server is running and the client needs access to
    dst_ip_addr :IpAddr,
    
    // port where server is eapecting the message to arrive
    // although the server will never bind to that port, it is just one more thing for
    // MITM and replay attacks to figure out
    dst_port :u16,

    // time when message was created (it is the unix time in miliseconds)
    // too long a window between creation and reception of message means some MITM activities
    // packet will be ignored
    creation_time :u64,

    // version of message protocol
    version: u16
}



fn handle_udp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let udp = UdpPacket::new(packet);
    let mut aes_key = [0u8; 32];
    let mut aes_iv = [0u8; 16];
    let cipher :Aes256Cbc;

    let settings :Settings; 
    match Settings::new(){
        Ok(setting) => {
            settings = setting; 
            // println!("{:?}", settings);
        },
        Err(e) => panic!("Could not find setting or load correctly {:?}",e)
    }


    // println!("{:?}", settings.clients.get("client1"));
    // println!("Pre shared key:{}, iv:{}", 
    //             client.pre_shared_key,
    //             client.pre_shared_iv );


    if let Some(udp) = udp {
        // println!(
        //     "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
        //     interface_name,
        //     source,
        //     udp.get_source(),
        //     destination,
        //     udp.get_destination(),
        //     udp.get_length()
        // );

        let dport = udp.get_destination();
        if (dport == settings.server.server_port) {
            println!("Got packet on secret port");

            // Get the payload
            let buf :&[u8] = udp.payload();
            let recvd_msg :WireProtoMessage = bincode::deserialize(buf).unwrap();
            println!("clinet_id= {}",recvd_msg.client_id );

            let client :&settings::Client= settings.clients.get(&recvd_msg.client_id).unwrap();

            pbkdf2::<Hmac<Sha256>>(&client.pre_shared_key.as_bytes(), &client.pre_shared_iv.as_bytes(), 10, &mut aes_key);    
            pbkdf2::<Hmac<Sha256>>(&client.pre_shared_iv.as_bytes(), &client.pre_shared_key.as_bytes(), 10, &mut aes_iv);
            
            match Aes256Cbc::new_from_slices(&aes_key, &aes_iv){
                Ok(ciphe) => {
                    cipher = ciphe;
                }
                Err(e) => panic!("{:?}", e)
            }

            let mut mac = HmacSha256::new_from_slice(&client.pre_shared_key.as_bytes())
                .expect("HMAC can take key of any size");

            
            let decrypted_ciphertext = cipher.decrypt_vec(&recvd_msg.enc_hmac_msg).unwrap();            
            println!("[Decrypted Message]: {:?}", decrypted_ciphertext);

            let recvd_hmac_proto_message : HmacProtoMessage = bincode::deserialize(&decrypted_ciphertext).unwrap();

            mac.update(&recvd_hmac_proto_message.message);
            // `verify` will return `Ok(())` if code is correct, `Err(MacError)` otherwise
            match mac.verify(&recvd_hmac_proto_message.hmac_vec){
                Ok(msg) => {println!("HAMC_MESSAGE:{:?}", msg);},
                Err(_) => panic!("HMAC could not verify message authenticity")
            }

            // In The actual implementation we will get encrypted payload from udp.payload()
            // This needs decryption using AES pre-shared key
            // Post decryption, we need to do HMAC verification
            // Once HMAC verification is done, we get to the actual message which contains ProtoMessage
            // Once we get handle on ProtoMessage, we extract the time and compare it to current system time
            // If the difference is greater than max_allowed_message_age_ms, we ignore the packet
            // If any of the steps fails, then we ignore the packet

            // Convert the payload from [u8] to str
            // let recv_message = str::from_utf8(&buf).unwrap();

            // Deserialize the received message str to ProtoMessage
            // let recvd_proto_message: ProtoMessage = serde_json::from_str(&recv_message).unwrap();
            // println!("[Deserialized ProtoMessage]:: {:?}", recvd_proto_message);
            //bincode message size is 1/3rd of json, so we changed to bincode in server and client
            
            let recvd_proto_message : ProtoMessage = bincode::deserialize(&recvd_hmac_proto_message.message).unwrap();
            println!("[Deserialized ProtoMessage]:: {:?}", recvd_proto_message);
            let now :u64;
            // let bincode_config = Configuration::standard();
            match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(n) => {
                        now = n.as_secs(); 
                        // println!("1970-01-01 00:00:00 UTC was {} seconds ago!", n.as_secs());
                }
                Err(_) => panic!("SystemTime before UNIX EPOCH!"),
            }
            if now > (MyConfig::default().max_allowed_message_age_ms/1000 +recvd_proto_message.creation_time) {
                println!("Message received after acceptable time window");
            } else {
                // We process the message
                println!("Timestamp is acceptable");
                // First let's get the packet, process it and then we can think of creating appropriate command
                // once proper command is formed, we can enable command execution
                let _ipfilter = Command::new("/usr/sbin/iptables")
                                .args(["-A", "INPUT", "-s", &source.to_string(), "-j", "ACCEPT"])
                                .status()
                                .expect("iptables failed to invoke");
            }

        }
    } else {
        println!("[{}]: Malformed UDP Packet", interface_name);
    }
}

// fn handle_icmp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
//     // let icmp_packet = IcmpPacket::new(packet);
//     // if let Some(icmp_packet) = icmp_packet {
//     //     match icmp_packet.get_icmp_type() {
//     //         IcmpTypes::EchoReply => {
//     //             let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
//     //             println!(
//     //                 "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
//     //                 interface_name,
//     //                 source,
//     //                 destination,
//     //                 echo_reply_packet.get_sequence_number(),
//     //                 echo_reply_packet.get_identifier()
//     //             );
//     //         }
//     //         IcmpTypes::EchoRequest => {
//     //             let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
//     //             println!(
//     //                 "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
//     //                 interface_name,
//     //                 source,
//     //                 destination,
//     //                 echo_request_packet.get_sequence_number(),
//     //                 echo_request_packet.get_identifier()
//     //             );
//     //         }
//     //         _ => println!(
//     //             "[{}]: ICMP packet {} -> {} (type={:?})",
//     //             interface_name,
//     //             source,
//     //             destination,
//     //             icmp_packet.get_icmp_type()
//     //         ),
//     //     }
//     // } else {
//     //     println!("[{}]: Malformed ICMP Packet", interface_name);
//     // }
// }

// fn handle_icmpv6_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
//     // let icmpv6_packet = Icmpv6Packet::new(packet);
//     // if let Some(icmpv6_packet) = icmpv6_packet {
//     //     println!(
//     //         "[{}]: ICMPv6 packet {} -> {} (type={:?})",
//     //         interface_name,
//     //         source,
//     //         destination,
//     //         icmpv6_packet.get_icmpv6_type()
//     //     )
//     // } else {
//     //     println!("[{}]: Malformed ICMPv6 Packet", interface_name);
//     // }
// }

// fn handle_tcp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
//     // let tcp = TcpPacket::new(packet);
//     // if let Some(tcp) = tcp {
//     //     println!(
//     //         "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
//     //         interface_name,
//     //         source,
//     //         tcp.get_source(),
//     //         destination,
//     //         tcp.get_destination(),
//     //         packet.len()
//     //     );
//     // } else {
//     //     println!("[{}]: Malformed TCP Packet", interface_name);
//     // }
// }


fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(interface_name, source, destination, packet)
        }
        _ => {

        }
        // _ => println!(
        //     "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
        //     interface_name,
        //     match source {
        //         IpAddr::V4(..) => "IPv4",
        //         _ => "IPv6",
        //     },
        //     source,
        //     destination,
        //     protocol,
        //     packet.len()
        // ),
    }
}



fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
        );
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
        );
    } else {
        println!("[{}]: Malformed IPv6 Packet", interface_name);
    }
}

fn handle_arp_packet(_interface_name: &str, _ethernet: &EthernetPacket) {
    // let header = ArpPacket::new(ethernet.payload());
    // if let Some(header) = header {
    //     // println!(
    //     //     "[{}]: ARP packet: {}({}) > {}({}); operation: {:?}",
    //     //     interface_name,
    //     //     ethernet.get_source(),
    //     //     header.get_sender_proto_addr(),
    //     //     ethernet.get_destination(),
    //     //     header.get_target_proto_addr(),
    //     //     header.get_operation()
    //     // );
    // } else {
    //     println!("[{}]: Malformed ARP Packet", interface_name);
    // }
}


fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket) {
    let interface_name = &interface.name[..];
    // println!("I am here 6");
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet),
        EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, ethernet),
        EtherTypes::Arp => handle_arp_packet(interface_name, ethernet),
        _ => println!(
            "[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
            interface_name,
            ethernet.get_source(),
            ethernet.get_destination(),
            ethernet.get_ethertype(),
            ethernet.packet().len()
        ),
    }
}


// Invoke as echo <interface name>

fn main(){
    // Load the settings/configurations
    let settings :Settings; 
    match Settings::new(){
        Ok(setting) => {
            settings = setting; 
            //println!("{:?}", settings);
        },
        Err(e) => panic!("Could not find setting or load correctly {:?}",e)
    }
  
    // let interface_name = env::args().nth(1).unwrap();
    let interface_name = settings.server.interface_name;
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
                                .filter(interface_names_match)
                                .next()
                                .unwrap();
    // Create a new channel, dealing with layer 2 packets
    let mut dconfig: Config = Default::default();
    dconfig.promiscuous = false;
    let mut rx = match datalink::channel(&interface, dconfig){
        Ok(Ethernet(_, rx)) => rx,
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    };
    
    loop {
        match rx.next() {
            Ok(packet) => {
                let rx_packet = EthernetPacket::new(packet).unwrap();
                // println!("{:?}", interface.mac);
                //If the interface on which we are operating is the source, no processing to be done 
                if rx_packet.get_source() != interface.mac.unwrap() {
                    handle_ethernet_frame(&interface, &rx_packet);
                }
            },
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
