use tun_tap::Iface;

use crate::ipv4::IPV4Header;

// =====================================================
//                    TCP HEADER
// =====================================================

#[derive(Debug, Default, Hash, PartialEq, Eq)]
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
    options: &'a [u8],
}

impl<'a> TcpHeader<'a> {
    pub fn build(buf: &'a [u8]) -> Self {
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
            options: &buf[20..header_length],
        }
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
        options: Option<&'a [u8]>,
        source_address: u32,
        destination_address:u32,
        payload: &'a [u8]
    ) -> Vec<u8> {
        //to calculate offset and checksum
        let mut buf = [0u8; 20];
        let options = options.unwrap_or(&[]);
        let mut offset = (5 + options.len() / 4) as u8;
        buf[0..2].copy_from_slice(&u16::to_be_bytes(source_port));
        buf[2..4].copy_from_slice(&u16::to_be_bytes(destination_port));
        buf[4..8].copy_from_slice(&u32::to_be_bytes(seq));
        buf[8..12].copy_from_slice(&u32::to_be_bytes(ack_number)); 
        buf[12] = offset << 4;
        buf[13] = ((cwr as u8) << 7) | ((ece as u8) << 6) | ((urg as u8) << 5) | ((ack_flag as u8) << 4) | ((psh as u8) << 3) | ((rst as u8) << 2) | ((syn as u8) << 1) | (fin  as u8);
        buf[14..16].copy_from_slice(&u16::to_be_bytes(window_size));
        //set checksum initially
        buf[16] = 0;
        buf[17] = 0;
        //end of checksum
        buf[18..20].copy_from_slice(&u16::to_be_bytes(urg_pointer));
        let mut vec = buf.to_vec();
        vec.extend_from_slice(&options);
        TcpHeader::calculate_checksum(&mut vec, source_address, destination_address, payload);

        vec
    }

    fn calculate_checksum(buf: &mut [u8], source_address: u32, destination_address:u32, payload: &[u8]) {
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

pub struct Connection {
    state: State,
    send_sequence: SendSequence,
    receive_sequence: ReceiveSequence,
}

struct SendSequence {
    una: usize,
    nxt: usize,
    wnd: usize,
    up: usize,
    wl1: usize,
    wl2: usize,
    iss: usize,
}

struct ReceiveSequence {
    nxt: usize,
    wnd: usize,
    up: usize,
    irs: usize,
}

impl Connection {
    pub fn on_packet<'a>(
        &mut self,
        nic: Iface,
        content: &'a [u8],
        tcp_header: TcpHeader,
        ipv4_header: IPV4Header,
    ) {
        match self.state {
            State::Closed => return,
            _ => return,
        }
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
