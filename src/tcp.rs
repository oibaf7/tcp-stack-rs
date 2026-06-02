use std::time::{SystemTime, UNIX_EPOCH};
use tun_tap::Iface;

use crate::ipv4::IPV4Header;
use crate::tcp_header::TcpHeader;
use crate::tcp_header::{TcpFlags, TcpOption};

const TUN_HEADER: [u8; 4] = [0x00, 0x00, 0x08, 0x00];
const DEFAULT_MSS: u16 = 1460;
const DEFAULT_WINDOW_SCALE: u8 = 0;
const TCP_DEFAULT_WINDOW_SIZE: u16 = 10;
const IPV4_DEFAULT_TTL: u8 = 64;
const IPV4_VERSION: u8 = 4;
const IPV4_PROTO_TCP: u8 = 6;

//discard sends back ack
enum Action {
    Proceed,
    Discard,
    RST,
    CloseConnection,
}

#[derive(Eq, PartialEq)]
pub enum State {
    Closed,
    Listen,
    SynRecvd,
    Estab,
    CloseWait,
    LastAck,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::Listen | State::SynRecvd => false,
            _ => true,
        }
    }
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
    pub una: u32,
    pub nxt: u32,
    pub wnd: u32,
    pub up: u32,
    pub wl1: u32,
    pub wl2: u32,
    pub iss: u32,
}

struct ReceiveSequence {
    pub nxt: u32,
    pub wnd: u32,
    pub up: u32,
    pub irs: u32,
}

impl Default for ReceiveSequence {
    fn default() -> Self {
        Self {
            nxt: 0,
            wnd: TCP_DEFAULT_WINDOW_SIZE as u32,
            up: 0,
            irs: 0,
        }
    }
}

//make refactor for unexpected receivals in each stage

impl Connection {
    pub fn get_state(&self) -> &State {
        &self.state
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &Iface,
        content: &'a [u8],
        tcp_header: &TcpHeader,
        ipv4_header: &IPV4Header,
    ) {

        if self.state == State::Closed {
            return;
        }

        let result = match self.state.is_synchronized() {
            true => self.handle_packet_synchronized(tcp_header, content),
            _ => self.handle_packet_unsynchronized(tcp_header, content),
        };

        match result {
            Action::Proceed => self.proceed_with_action(nic, tcp_header, ipv4_header, content),
            //send with no body to not change next sequence number
            Action::Discard => self.send_ack(nic, tcp_header, ipv4_header, &[]),
            Action::RST => self.send_rst(nic, tcp_header, ipv4_header),
            Action::CloseConnection => self.state = State::Closed,
        }

    }

    fn proceed_with_action(&mut self, nic: &Iface, tcp_header: &TcpHeader, ipv4_header: &IPV4Header, content: &[u8]) {
        match self.state {
            State::Closed => return,
            State::Listen => self.send_syn_ack(nic, tcp_header, ipv4_header),
            State::SynRecvd => {
                self.update_state_after_handshake(nic, tcp_header, ipv4_header);
            }
            State::Estab => {
                if tcp_header.is_fin() {
                    self.state = State::CloseWait;
                    self.receive_sequence.nxt += 1;
                    self.send_fin(nic, tcp_header, ipv4_header);
                    return;
                }

                self.send_ack(nic, tcp_header, ipv4_header, content);
            }
            State::LastAck => self.state = State::Closed,
            _ => return,
        }
    }

    fn send_syn_ack(&mut self, nic: &Iface, tcp_header: &TcpHeader, ipv4_header: &IPV4Header) {
        self.state = State::SynRecvd;
        self.send_sequence.nxt = Self::generate_isn();
        self.send_sequence.una = self.send_sequence.nxt;
        self.send_sequence.wnd = tcp_header.get_window_size() as u32;
        self.receive_sequence.irs = tcp_header.get_sequence_number();
        self.receive_sequence.wnd = TCP_DEFAULT_WINDOW_SIZE as u32;
        self.receive_sequence.nxt = tcp_header.get_sequence_number() + 1;
        let mut vec = Vec::from(TUN_HEADER);
        let timestamp = tcp_header.get_options().iter().find(|x| {
            return match x {
                TcpOption::Timestamp { .. } => true,
                _ => false,
            };
        });
        let options: Vec<TcpOption> = Self::extract_option(timestamp);
        let flags = TcpFlags {
            syn: true,
            ack_flag: true,
            ..Default::default()
        };
        let new_tcp_header = self.make_tcp_header(tcp_header, ipv4_header, flags, &options);
        let new_ipv4_header = Self::make_ipv4_header(&new_tcp_header, ipv4_header);
        vec.extend_from_slice(&new_ipv4_header[..]);
        vec.extend_from_slice(&new_tcp_header[..]);
        nic.send(&vec).expect("unable to send");
        self.send_sequence.nxt += 1;
    }

    fn update_state_after_handshake(
        &mut self,
        nic: &Iface,
        tcp_header: &TcpHeader,
        ipv4_header: &IPV4Header,
    ) {
        self.state = State::Estab;
        self.send_sequence.wnd = tcp_header.get_window_size() as u32;
    }

    fn send_ack<'a>(
        &mut self,
        nic: &Iface,
        tcp_header: &TcpHeader,
        ipv4_header: &IPV4Header,
        content: &'a [u8],
    ) {
        self.receive_sequence.nxt += content.len() as u32;
        let mut vec = Vec::from(TUN_HEADER);
        let timestamp = tcp_header.get_options().iter().find(|x| {
            return match x {
                TcpOption::Timestamp { .. } => true,
                _ => false,
            };
        });
        let options: Vec<TcpOption> = Self::extract_option(timestamp);
        let flags = TcpFlags {
            ack_flag: true,
            ..Default::default()
        };
        let new_tcp_header = self.make_tcp_header(tcp_header, ipv4_header, flags, &options);
        let new_ipv4_header = Self::make_ipv4_header(&new_tcp_header, ipv4_header);
        vec.extend_from_slice(&new_ipv4_header[..]);
        vec.extend_from_slice(&new_tcp_header[..]);
        nic.send(&vec).expect("unable to send");
    }

    fn send_fin(&mut self, nic: &Iface, tcp_header: &TcpHeader, ipv4_header: &IPV4Header) {
        self.state = State::LastAck;
        let mut vec = Vec::from(TUN_HEADER);
        let timestamp = tcp_header.get_options().iter().find(|x| {
            return match x {
                TcpOption::Timestamp { .. } => true,
                _ => false,
            };
        });
        let options: Vec<TcpOption> = Self::extract_option(timestamp);
        let flags = TcpFlags {
            fin: true,
            ack_flag: true,
            ..Default::default()
        };
        let new_tcp_header = self.make_tcp_header(tcp_header, ipv4_header, flags, &options);
        let new_ipv4_header = Self::make_ipv4_header(&new_tcp_header, ipv4_header);
        vec.extend_from_slice(&new_ipv4_header[..]);
        vec.extend_from_slice(&new_tcp_header[..]);
        nic.send(&vec).expect("unable to send");
    }

    fn send_rst(&mut self, nic: &Iface, tcp_header: &TcpHeader, ipv4_header: &IPV4Header) {
        self.state = State::Closed;
        let mut vec = Vec::from(TUN_HEADER);
        let timestamp = tcp_header.get_options().iter().find(|x| {
            return match x {
                TcpOption::Timestamp { .. } => true,
                _ => false,
            };
        });
        let options: Vec<TcpOption> = Self::extract_option(timestamp);
        let flags = TcpFlags {
            rst: true,
            ..Default::default()
        };
        let new_tcp_header = self.make_tcp_header(tcp_header, ipv4_header, flags, &options);
        let new_ipv4_header = Self::make_ipv4_header(&new_tcp_header, ipv4_header);
        vec.extend_from_slice(&new_ipv4_header[..]);
        vec.extend_from_slice(&new_tcp_header[..]);
        nic.send(&vec).expect("unable to send");
    }

    //eventually look into determining options based on state (syn vs ack etc...)
    fn extract_option<'a>(timestamp: Option<&TcpOption>) -> Vec<TcpOption<'a>> {
        match timestamp {
            Some(TcpOption::Timestamp { tsval, .. }) => vec![
                TcpOption::Mss(DEFAULT_MSS),
                TcpOption::SackPermitted,
                TcpOption::Timestamp {
                    tsval: 0,
                    tsecr: *tsval,
                },
                TcpOption::WindowScale(DEFAULT_WINDOW_SCALE),
            ],
            _ => vec![TcpOption::Mss(1460)],
        }
    }

    fn make_tcp_header(
        &self,
        tcp_header: &TcpHeader,
        ipv4_header: &IPV4Header,
        flags: TcpFlags,
        options: &[TcpOption],
    ) -> Vec<u8> {
        TcpHeader::build_raw_header(
            tcp_header.get_destination_port(),
            tcp_header.get_source_port(),
            self.send_sequence.nxt,
            self.receive_sequence.nxt,
            flags,
            10,
            0,
            Some(&options),
            ipv4_header.get_destination_address(),
            ipv4_header.get_source_address(),
            &[],
        )
    }

    fn make_ipv4_header(tcp_header: &[u8], ipv4_header: &IPV4Header) -> Vec<u8> {
        IPV4Header::build_raw_header(
            IPV4_VERSION,
            5,
            0,
            0,
            20 + (tcp_header.len() as u16),
            0,
            0,
            0,
            IPV4_DEFAULT_TTL,
            IPV4_PROTO_TCP,
            ipv4_header.get_destination_address(),
            ipv4_header.get_source_address(),
            None,
        )
    }

    fn generate_isn() -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u32
    }

    fn validity_of_ack(unack: u32, ack: u32, nxt: u32) -> bool {
        if unack < nxt {
            if unack < ack && ack <= nxt {
                return true;
            }
        } else {
            if (unack < ack && nxt < ack) || (unack > ack && nxt >= ack) {
                return true;
            }
        }

        false
    }

    fn validity_of_seq(nxt: u32, seq: u32, nxt_and_wnd: u32) -> bool {
        if nxt < nxt_and_wnd {
            if nxt <= seq && seq < nxt_and_wnd {
                return true;
            }
        } else {
            if (nxt <= seq && nxt_and_wnd < seq) || (nxt > seq && nxt_and_wnd > seq) {
                return true;
            }
        }

        false
    }

    fn perform_seq_validity_check(&self, tcp_header: &TcpHeader, content: &[u8]) -> bool {
        let seq = tcp_header.get_sequence_number();
        let mut len = content.len();
        if tcp_header.is_fin() {
            len += 1
        };
        if tcp_header.is_syn() {
            len += 1
        };
        let seq_end = seq.wrapping_add(len as u32).wrapping_sub(1);
        let acceptable_seq = if len == 0 {
            if self.receive_sequence.wnd == 0 {
                seq == self.receive_sequence.nxt
            } else {
                Self::validity_of_seq(
                    self.receive_sequence.nxt,
                    seq,
                    self.receive_sequence.nxt + self.receive_sequence.wnd,
                )
            }
        } else {
            //check both so you can acknowledge at least one byte from the segment
            (Self::validity_of_seq(
                self.receive_sequence.nxt,
                seq,
                self.receive_sequence.nxt + self.receive_sequence.wnd,
            ) || Self::validity_of_seq(
                self.receive_sequence.nxt,
                seq_end,
                self.receive_sequence.nxt + self.receive_sequence.wnd,
            )) && self.receive_sequence.wnd != 0
        };
        acceptable_seq
    }

    fn handle_packet_synchronized(&mut self, tcp_header: &TcpHeader, content: &[u8]) -> Action {
        if !self.perform_seq_validity_check(tcp_header, content) {
            return Action::Discard;
        }

        if tcp_header.is_rst() {
            return Action::CloseConnection;
        }

        if tcp_header.is_syn() {
            return Action::Discard;
        }

        if !Self::validity_of_ack(
            self.send_sequence.una,
            tcp_header.get_acknowledgment_number(),
            self.send_sequence.nxt,
        ) {
            return Action::RST;
        }

        Action::Proceed
    }

    fn handle_packet_unsynchronized(&mut self, tcp_header: &TcpHeader, content: &[u8]) -> Action {
        if self.state == State::SynRecvd && !self.perform_seq_validity_check(tcp_header, content) {
            return Action::Discard;
        }

        if tcp_header.is_rst() {
            return Action::CloseConnection;
        }

        if tcp_header.is_syn() && self.state == State::SynRecvd {
            return Action::RST;
        }

        if !Self::validity_of_ack(
            self.send_sequence.una,
            tcp_header.get_acknowledgment_number(),
            self.send_sequence.nxt,
        ) {
            return Action::RST;
        }

        Action::Proceed
    }
}

