#[derive(Debug)]
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
            options: &buf[20..header_length]
        } 

    }

    pub fn get_header_length(&self) -> usize {
        (self.offset * 4) as usize
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
}
