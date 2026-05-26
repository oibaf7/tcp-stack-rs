use tun_tap::Iface;

use crate::ipv4::IPV4Header;
use crate::tcp::TcpOption::Unknown;
// =====================================================
//                    TCP HEADER
// =====================================================

pub struct TcpHeader<'a> {
    source_port: u16,
    destination_port: u16,
    seq: u32,
    ack_number: u32,
    offset: u8,
    cwr: bool,
    ece: bool,
    urg: bool,
    ack_flag: bool,
    psh: bool,
    rst: bool,
    syn: bool,
    fin: bool,
    window_size: u16,
    checksum: u16,
    urg_pointer: u16,
    options: Vec<TcpOption<'a>>,
}

impl<'a> TcpHeader<'a> {
    pub fn build(buf: &'a[u8]) -> Self {
        let (source_port, destination_port) = TcpHeader::get_source_and_destination_port(buf);
        let seq = TcpHeader::get_sequence_number(buf);
        let ack_number = TcpHeader::get_ack_number(buf);
        let offset = TcpHeader::get_offset(buf[12]);
        let (cwr, ece, urg, ack_flag, psh, rst, syn, fin) = TcpHeader::get_flags(buf[13]);
        let window_size = TcpHeader::get_window(buf);
        let checksum = TcpHeader::get_checksum(buf);
        let urg_pointer = TcpHeader::get_urg_pointer(buf);
        let header_length = (offset * 4) as usize;
        Self {
            source_port,
            destination_port,
            seq,
            ack_number,
            offset,
            cwr,
            ece,
            urg,
            ack_flag,
            psh,
            rst,
            syn,
            fin,
            window_size,
            checksum,
            urg_pointer,
            options: parse_options(&buf[20..header_length]),
        }
    }

    pub fn get_source_port(&self) -> u16 {
        self.source_port
    }

    pub fn get_destination_port(&self) -> u16 {
        self.destination_port
    }

    pub fn get_header_length(&self) -> usize {
        (self.offset * 4) as usize
    }

    pub fn is_syn(&self) -> bool {
        self.syn
    }

    pub fn is_ack(&self) -> bool {
        self.ack_flag
    }

    fn get_source_and_destination_port(buf: &[u8]) -> (u16, u16) {
        let source_port = u16::from_be_bytes([buf[0], buf[1]]);
        let destination_port = u16::from_be_bytes([buf[2], buf[3]]);
        (source_port, destination_port)
    }

    fn get_sequence_number(buf: &[u8]) -> u32 {
        u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]])
    }

    fn get_ack_number(buf: &[u8]) -> u32 {
        u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]])
    }

    fn get_offset(value: u8) -> u8 {
        (value >> 4) & 0xF
    }

    fn get_flags(value: u8) -> (bool, bool, bool, bool, bool, bool, bool, bool) {
        (
            value >> 7 == 1,
            (value >> 6 & 1) == 1,
            (value >> 5 & 1) == 1,
            (value >> 4 & 1) == 1,
            (value >> 3 & 1) == 1,
            (value >> 2 & 1) == 1,
            (value >> 1 & 1) == 1,
            (value & 1) == 1,
        )
    }

    fn get_window(buf: &[u8]) -> u16 {
        u16::from_be_bytes([buf[14], buf[15]])
    }

    fn get_checksum(buf: &[u8]) -> u16 {
        u16::from_be_bytes([buf[16], buf[17]])
    }

    fn get_urg_pointer(buf: &[u8]) -> u16 {
        u16::from_be_bytes([buf[18], buf[19]])
    }

    pub fn build_raw_header(
        source_port: u16,
        destination_port: u16,
        seq: u32,
        ack_number: u32,
        cwr: bool,
        ece: bool,
        urg: bool,
        ack_flag: bool,
        psh: bool,
        rst: bool,
        syn: bool,
        fin: bool,
        window_size: u16,
        urg_pointer: u16,
        options: Option<&Vec<TcpOption<'_>>>,
        source_address: u32,
        destination_address: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        //to calculate offset and checksum
        let mut buf = [0u8; 20];
        let options = build_options(options.unwrap_or(&Vec::new()));
        let offset = (5 + options.len() / 4) as u8;
        buf[0..2].copy_from_slice(&u16::to_be_bytes(source_port));
        buf[2..4].copy_from_slice(&u16::to_be_bytes(destination_port));
        buf[4..8].copy_from_slice(&u32::to_be_bytes(seq));
        buf[8..12].copy_from_slice(&u32::to_be_bytes(ack_number));
        buf[12] = offset << 4;
        buf[13] = ((cwr as u8) << 7)
            | ((ece as u8) << 6)
            | ((urg as u8) << 5)
            | ((ack_flag as u8) << 4)
            | ((psh as u8) << 3)
            | ((rst as u8) << 2)
            | ((syn as u8) << 1)
            | (fin as u8);
        buf[14..16].copy_from_slice(&u16::to_be_bytes(window_size));
        //set checksum initially
        buf[16] = 0;
        buf[17] = 0;
        //end of checksum
        buf[18..20].copy_from_slice(&u16::to_be_bytes(urg_pointer));
        let mut vec = buf.to_vec();
        vec.extend_from_slice(options.as_slice());
        TcpHeader::calculate_checksum(&mut vec, source_address, destination_address, payload);

        vec
    }

    fn calculate_checksum(
        buf: &mut [u8],
        source_address: u32,
        destination_address: u32,
        payload: &[u8],
    ) {
        let mut sum = 0u32;
        let chunks = buf.chunks_exact(2);
        for chunk in chunks {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        sum += (buf.len() + payload.len()) as u32;
        sum += 6u32; // protocol
        sum += source_address >> 16;
        sum += source_address & 0xFFFF;
        sum += destination_address >> 16;
        sum += destination_address & 0xFFFF;

        let chunks = payload.chunks_exact(2);
        for chunk in chunks {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }

        let mut remainder = sum >> 16;
        while remainder != 0 {
            sum += remainder;
            remainder = sum >> 16;
        }

        buf[16..18].copy_from_slice(&u16::to_be_bytes(!(sum as u16)));
    }
}

pub enum TcpOption<'a> {
    Nop,
    Mss(u16),
    WindowScale(u8),
    SackPermitted,
    Sack(&'a [u8]),
    UserTimeoutOption(u16),
    TcpAo(&'a [u8]),
    MPTCP(&'a [u8]),
    Timestamp { tsval: u32, tsecr: u32 },
    Unknown { kind: u8, data: &'a [u8] },
}

fn parse_options(raw: &'_ [u8]) -> Vec<TcpOption<'_>> {
    let mut vec = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            0u8 => break,
            1u8 => {
                vec.push(TcpOption::Nop);
                i += 1;
            }
            2u8 => {
                if i + 3 >= raw.len() {
                    break;
                }
                vec.push(TcpOption::Mss(u16::from_be_bytes([raw[i + 2], raw[i + 3]])));
                i += 4;
            }
            3u8 => {
                if i + 2 >= raw.len() {
                    break;
                }
                vec.push(TcpOption::WindowScale(raw[i + 2]));
                i += 3;
            }
            4u8 => {
                vec.push(TcpOption::SackPermitted);
                i += 2;
            }
            5u8 => {
                if i + 1 >= raw.len() {
                    break;
                }
                let length = match read_length(raw[i + 1], i, raw.len()) {
                    Some(l) => l,
                    None => break,
                };
                vec.push(TcpOption::Sack(&raw[i..(i + length)]));
                i += length;
            }
            8u8 => {
                if i + 9 >= raw.len() {
                    break;
                }
                vec.push(TcpOption::Timestamp {
                    tsval: u32::from_be_bytes([raw[i + 2], raw[i + 3], raw[i + 4], raw[i + 5]]),
                    tsecr: u32::from_be_bytes([raw[i + 6], raw[i + 7], raw[i + 8], raw[i + 9]]),
                });
                i += 10;
            }
            28u8 => {
                if i + 3 >= raw.len() {
                    break;
                }
                vec.push(TcpOption::UserTimeoutOption(u16::from_be_bytes([
                    raw[i + 2],
                    raw[i + 3],
                ])));
                i += 4;
            }
            29u8 => {
                if i + 1 >= raw.len() {
                    break;
                }
                let length = match read_length(raw[i + 1], i, raw.len()) {
                    Some(l) => l,
                    None => break,
                };
                vec.push(TcpOption::TcpAo(&raw[i..(i + length)]));
                i += length;
            }
            30u8 => {
                if i + 1 >= raw.len() {
                    break;
                }
                let length = match read_length(raw[i + 1], i, raw.len()) {
                    Some(l) => l,
                    None => break,
                };
                vec.push(TcpOption::MPTCP(&raw[i..(i + length)]));
                i += length;
            }
            _ => {
                if i + 1 >= raw.len() {
                    break;
                }
                let length = match read_length(raw[i + 1], i, raw.len()) {
                    Some(l) => l,
                    None => break,
                };
                vec.push(Unknown {
                    kind: raw[i],
                    data: &raw[i + 2..i + length],
                });
                i += length;
            }
        }
    }
    vec
}

fn read_length(length: u8, i: usize, raw_length: usize) -> Option<usize> {
    if length < 2 || i + length as usize > raw_length {
        return None;
    }
    Some(length as usize)
}
fn build_options(opts: &[TcpOption]) -> Vec<u8> {
    let mut vec = Vec::new();
    for opt in opts {
        match opt {
            TcpOption::Nop => vec.push(1),
            TcpOption::Mss(v) => {
                vec.push(2);
                vec.push(4);
                vec.extend_from_slice(&v.to_be_bytes());
            }
            TcpOption::WindowScale(v) => {
                vec.push(3);
                vec.push(4);
                vec.push(*v);
            }
            TcpOption::SackPermitted => {
                vec.push(4);
                vec.push(2);
            }
            TcpOption::Sack(v) => {
                vec.push(5);
                vec.push(2 + v.len() as u8);
                vec.extend_from_slice(v);
            }
            TcpOption::Timestamp {
                tsval: v1,
                tsecr: v2,
            } => {
                vec.push(8);
                vec.push(10);
                vec.extend_from_slice(&u32::to_be_bytes(*v1));
                vec.extend_from_slice(&u32::to_be_bytes(*v2));
            }
            TcpOption::UserTimeoutOption(v) => {
                vec.push(28);
                vec.push(4);
                vec.extend_from_slice(&u16::to_be_bytes(*v));
            }
            TcpOption::TcpAo(v) => {
                vec.push(29);
                vec.push(2 + v.len() as u8);
                vec.extend_from_slice(v);
            }
            TcpOption::MPTCP(v) => {
                vec.push(30);
                vec.push(2 + v.len() as u8);
                vec.extend_from_slice(v);
            }
            TcpOption::Unknown { kind: v1, data: v2 } => {
                vec.push(*v1);
                vec.push(2 + v2.len() as u8);
                vec.extend_from_slice(v2);
            }
        }
    }
    let pad = (4 - (vec.len() % 4)) % 4;
    for i in 0..pad {
        vec.push(1);
    }
    vec.push(0);
    vec
}

// =====================================================
//                 TCP CONNECTION STATE
// =====================================================

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
        eprintln!("hello");
        self.state = State::SynRecvd;
        let mut vec = vec![0u8, 0u8, 8u8, 0u8];
        let new_ipv4_header = IPV4Header::build_raw_header(
            4,
            5,
            0,
            0,
            40,
            0,
            0,
            0,
            64,
            6,
            ipv4_header.get_destination_address(),
            ipv4_header.get_source_address(),
            None,
        );

        let new_tcp_header = TcpHeader::build_raw_header(
            tcp_header.get_destination_port(),
            tcp_header.get_source_port(),
            0,
            tcp_header.seq + 1,
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
            None,
            ipv4_header.get_destination_address(),
            ipv4_header.get_source_address(),
            &[],
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
