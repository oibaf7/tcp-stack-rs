use tcp_stack::{ipv4, tcp};
use tun_tap::{Iface, Mode};

fn main() {
    let iface = Iface::new("tun0", Mode::Tun).expect("failed!");

    let mut buf = [0u8; 1504];
    loop {
        let nbytes = iface.recv(&mut buf).expect("failed to recv");
        let eth_flags = u16::from_be_bytes([buf[0], buf[1]]); //link level information
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]); //ipv4 if 0x0800
        if eth_proto != 0x0800 {
            continue;
        };
        let ipv4_header = ipv4::IPV4Header::build(&buf[4..nbytes]);
        let ipv4_header_length = (ipv4_header.get_ihl() * 4) as usize;
        if ipv4_header.get_protocol() != 0x6 {
            continue;
        }
        let tcp_header = tcp::TcpHeader::build(&buf[4 + ipv4_header_length..]);
        eprintln!(
            "received {} proto: {:x} ipv4 header: {:#?} tcp header: {:#?} bytes: {:?}",
            nbytes - 4,
            eth_proto,
            ipv4_header,
            tcp_header,
            &buf[..]
        );
    }
}
