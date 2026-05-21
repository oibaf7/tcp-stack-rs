use tcp_stack::ipv4;
use tun_tap::{Iface, Mode};

fn main() {
    let iface = Iface::new("tun0", Mode::Tun).expect("failed!");

    let mut buf = [0u8; 1504];
    loop {
        let nbytes = iface.recv(&mut buf).expect("failed to recv");
        let flags = u16::from_be_bytes([buf[0], buf[1]]);
        let proto = u16::from_be_bytes([buf[2], buf[3]]); //ipv4 if 0x0800
        let header = ipv4::IPV4Header::build(&buf[4..]);
        if proto != 0x0800 {
            continue;
        };
        eprintln!(
            "received {} proto: {:x} bytes: {:?}",
            nbytes - 4,
            proto,
            &buf[4..nbytes]
        );
    }
}
