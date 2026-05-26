use std::collections::HashMap;

use tcp_stack::tcp::Connection;
use tcp_stack::{ipv4, tcp};
use tun_tap::{Iface, Mode};

//move somewhere else eventually
#[derive(Default, Hash, PartialEq, Eq)]
struct ConnectionKey {
    //ip address, port number
    source: (u32, u16),
    destination: (u32, u16),
}

fn main() {
    let iface = Iface::new("tun0", Mode::Tun).expect("failed!");
    let mut connections: HashMap<ConnectionKey, tcp::Connection> = HashMap::new();
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = iface.recv(&mut buf).expect("failed to recv");
        let eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        if eth_proto != 0x0800 {
            continue;
        };
        let ipv4_header = ipv4::IPV4Header::build(&buf[4..nbytes]);
        let ipv4_header_length = ipv4_header.get_header_length();
        if ipv4_header.get_protocol() != 0x0006 {
            continue;
        }
        let tcp_header = tcp::TcpHeader::build(&buf[4 + ipv4_header_length..nbytes]);
        let tcp_header_length = tcp_header.get_header_length();
        let payload = &buf[4 + ipv4_header_length + tcp_header_length..nbytes];
        //check if in hashmap, if not create connection, do on packet, on packet should handle everything
        let connectionKey = ConnectionKey {
            source: (
                ipv4_header.get_source_address(),
                tcp_header.get_source_port(),
            ),
            destination: (
                ipv4_header.get_destination_address(),
                tcp_header.get_source_port(),
            ),
        };
        let connection = connections.get_mut(&connectionKey);
        if let Some(c) = connection {
            c.on_packet(&iface, payload, &tcp_header, &ipv4_header);
        } else {
            let mut c = Connection::default();
            c.on_packet(&iface, payload, &tcp_header, &ipv4_header);
            connections.insert(connectionKey, c);
        }

        
    }
}
