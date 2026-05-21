use tun_tap::{Iface, Mode};

fn main() {
    let iface = Iface::new("tun0", Mode::Tun).expect("failed!");

    let mut buf = [0u8; 1504];
    loop {
        let nbytes = iface.recv(&mut buf).expect("failed to recv");
        eprintln!("received {} bytes: {:?}", nbytes, &buf[..nbytes]);
    }
}
