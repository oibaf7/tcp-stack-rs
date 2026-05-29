use tun_tap::Iface;

use crate::ipv4::IPV4Header;
use crate::tcp_header::TcpOption;
use crate::tcp_header::TcpHeader;
// =====================================================
//                    TCP HEADER
// =====================================================

// =====================================================
//                 TCP CONNECTION STATE
// =====================================================

const TUN_HEADER: [u8; 4] = [0x00, 0x00, 0x08, 0x00];
const DEFAULT_MSS: u16 = 1460;
const DEFAULT_WINDOW_SCALE: u8 = 0;
const TCP_DEFAULT_WINDOW_SIZE: u16 = 10;
const IPV4_DEFAULT_TTL: u8 = 64;
const IPV4_VERSION: u8 = 4;
const IPV4_PROTO_TCP: u8 = 6;

pub enum State {
    Closed,
    Listen,
    SynSent,
    SynRecvd,
    Estab,
}

impl Default for State {
    fn default() -> Self {
        Self::Listen
    }
}

#[derive(Default)]
pub struct Connection {
    state: State,
    send_sequence: SendSequence,
    receive_sequence: ReceiveSequence,
}

#[derive(Default)]
struct SendSequence {
    una: usize,
    nxt: usize,
    wnd: usize,
    up: usize,
    wl1: usize,
    wl2: usize,
    iss: usize,
}

#[derive(Default)]
struct ReceiveSequence {
    nxt: usize,
    wnd: usize,
    up: usize,
    irs: usize,
}

impl Connection {
    pub fn on_packet<'a>(
        &mut self,
        nic: &Iface,
        content: &'a [u8],
        tcp_header: &TcpHeader,
        ipv4_header: &IPV4Header,
    ) {
        match self.state {
            State::Closed => return,
            State::Listen => self.send_syn_ack(nic, &tcp_header, &ipv4_header),
            State::SynRecvd => self.send_syn_ack(nic, tcp_header, ipv4_header),
            _ => return,
        }
    }

    fn send_syn_ack(&mut self, nic: &Iface, tcp_header: &TcpHeader, ipv4_header: &IPV4Header) {
        //consider checking new sequence number, also updating state!
        self.state = State::SynRecvd;
        let mut vec = Vec::from(TUN_HEADER);
        let timestamp = tcp_header.get_options().iter().find(|x| {
            return match x {
                TcpOption::Timestamp { .. } => true,
                _ => false,
            };
        });
        let options: Vec<TcpOption> = match timestamp {
            Some(TcpOption::Timestamp {tsval, ..}) => vec![
                TcpOption::Mss(DEFAULT_MSS),
                TcpOption::SackPermitted,
                TcpOption::Timestamp { tsval: 0, tsecr: *tsval },
                TcpOption::WindowScale(DEFAULT_WINDOW_SCALE),
            ],
            _ => vec![TcpOption::Mss(1460)],
        };
        let new_tcp_header = TcpHeader::build_raw_header(
            tcp_header.get_destination_port(),
            tcp_header.get_source_port(),
            0,
            tcp_header.get_sequence_number().wrapping_add(1),
            false,
            false,
            false,
            true,
            false,
            false,
            true,
            false,
            10,
            0,
            Some(&options),
            ipv4_header.get_destination_address(),
            ipv4_header.get_source_address(),
            &[],
        );
        let new_ipv4_header = IPV4Header::build_raw_header(
            IPV4_VERSION,
            5,
            0,
            0,
            20 + (new_tcp_header.len() as u16),
            0,
            0,
            0,
            IPV4_DEFAULT_TTL,
            IPV4_PROTO_TCP,
            ipv4_header.get_destination_address(),
            ipv4_header.get_source_address(),
            None,
        );
        vec.extend_from_slice(&new_ipv4_header[..]);
        vec.extend_from_slice(&new_tcp_header[..]);
        nic.send(&vec).expect("unable to send");
    }
}
//                               +---------+ ---------\      active OPEN
//                               |  CLOSED |            \    -----------
//                               +---------+<---------\   \   create TCB
//                                 |     ^              \   \  snd SYN
//                    passive OPEN |     |   CLOSE        \   \
//                    ------------ |     | ----------       \   \
//                     create TCB  |     | delete TCB         \   \
//                                 V     |                      \   \
//                               +---------+            CLOSE    |    \
//                               |  LISTEN |          ---------- |     |
//                               +---------+          delete TCB |     |
//                    rcv SYN      |     |     SEND              |     |
//                   -----------   |     |    -------            |     V
//  +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
//  |         |<-----------------           ------------------>|         |
//  |   SYN   |                    rcv SYN                     |   SYN   |
//  |   RCVD  |<-----------------------------------------------|   SENT  |
//  |         |                    snd ACK                     |         |
//  |         |------------------           -------------------|         |
//  +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
//    |           --------------   |     |   -----------
//    |                  x         |     |     snd ACK
//    |                            V     V
//    |  CLOSE                   +---------+
//    | -------                  |  ESTAB  |
//    | snd FIN                  +---------+
//    |                   CLOSE    |     |    rcv FIN
//    V                  -------   |     |    -------
//  +---------+          snd FIN  /       \   snd ACK          +---------+
//  |  FIN    |<-----------------           ------------------>|  CLOSE  |
//  | WAIT-1  |------------------                              |   WAIT  |
//  +---------+          rcv FIN  \                            +---------+
//    | rcv ACK of FIN   -------   |                            CLOSE  |
//    | --------------   snd ACK   |                           ------- |
//    V        x                   V                           snd FIN V
//  +---------+                  +---------+                   +---------+
//  |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
//  +---------+                  +---------+                   +---------+
//    |                rcv ACK of FIN |                 rcv ACK of FIN |
//    |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
//    |  -------              x       V    ------------        x       V
//     \ snd ACK                 +---------+delete TCB         +---------+
//      ------------------------>|TIME WAIT|------------------>| CLOSED  |
//                               +---------+                   +---------+

//                       TCP Connection State Diagram
//                                Figure 6.
