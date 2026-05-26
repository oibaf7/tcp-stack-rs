#[derive(Debug, Default, Hash, PartialEq, Eq)]
pub struct IPV4Header<'a> {
    version: u8,
    ihl: u8,
    dspc: u8,
    ecn: u8,
    total_length: u16,
    id: u16,
    flags: u8,
    offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    source_address: u32,
    destination_address: u32,
    options: &'a [u8],
}

//[vvvv, iiii] high low per byte

impl<'a> IPV4Header<'a> {
    pub fn build(buf: &'a [u8]) -> Self {
        let (version, ihl) = IPV4Header::get_version_and_ihl(buf[0]);
        let (dspc, ecn) = IPV4Header::get_dscp_and_ecn(buf[1]);
        let total_length = IPV4Header::get_total_length(buf);
        let id = IPV4Header::get_id(buf);
        let (flags, offset) = IPV4Header::get_flags_and_offset(buf);
        let (ttl, protocol) = IPV4Header::get_ttl_and_protocol(buf);
        let checksum = IPV4Header::get_checksum(buf);
        let (source_address, destination_address) =
            IPV4Header::get_source_and_destination_address(buf);
        let header_length = 4 * ihl as usize;
        Self {
            version,
            ihl,
            dspc,
            ecn,
            total_length,
            id,
            flags,
            offset,
            ttl,
            protocol,
            checksum,
            source_address,
            destination_address,
            options: &buf[20..header_length],
        }
    }

    pub fn get_source_address(&self) -> u32 {
        self.source_address
    }

    pub fn get_destination_address(&self) -> u32 {
        self.destination_address
    }

    pub fn get_header_length(&self) -> usize {
        (self.ihl * 4) as usize
    }

    pub fn get_protocol(&self) -> u8 {
        self.protocol
    }

    fn get_version_and_ihl(value: u8) -> (u8, u8) {
        ((value >> 4) & 0xF, value & 0xF)
    }

    fn get_dscp_and_ecn(value: u8) -> (u8, u8) {
        ((value >> 2) & 0x3F, value & 0x3)
    }

    fn get_total_length(buf: &[u8]) -> u16 {
        u16::from_be_bytes([buf[2], buf[3]])
    }

    fn get_id(buf: &[u8]) -> u16 {
        u16::from_be_bytes([buf[4], buf[5]])
    }

    fn get_flags_and_offset(buf: &[u8]) -> (u8, u16) {
        let value = u16::from_be_bytes([buf[6], buf[7]]);
        (((value >> 13) & 0x7) as u8, value & 0x1FFF)
    }

    fn get_ttl_and_protocol(buf: &[u8]) -> (u8, u8) {
        (buf[8], buf[9])
    }

    fn get_checksum(buf: &[u8]) -> u16 {
        u16::from_be_bytes([buf[10], buf[11]])
    }

    fn get_source_and_destination_address(buf: &[u8]) -> (u32, u32) {
        (
            u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
            u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]),
        )
    }

    pub fn build_raw_header(
        version: u8,
        ihl: u8,
        dspc: u8,
        ecn: u8,
        total_length: u16,
        id: u16,
        flags: u8,
        offset: u16,
        ttl: u8,
        protocol: u8,
        source_address: u32,
        destination_address: u32,
        options: Option<&'a [u8]>,
    ) -> Vec<u8> {
        let mut buf = [0u8; 20];
        let options = options.unwrap_or(&[]);
        buf[0] = (version << 4) | ihl;
        buf[1] = (dspc << 2) | ecn;
        buf[2..4].copy_from_slice(&u16::to_be_bytes(total_length));
        buf[4..6].copy_from_slice(&u16::to_be_bytes(id));
        buf[6..8].copy_from_slice(&u16::to_be_bytes(((flags as u16) << 13) | offset));
        buf[8] = ttl;
        buf[9] = protocol;
        //checksum setup
        buf[10] = 0;
        buf[11] = 0;
        //checksum setup end
        buf[12..16].copy_from_slice(&u32::to_be_bytes(source_address));
        buf[16..20].copy_from_slice(&u32::to_be_bytes(destination_address));
        let mut vec = buf.to_vec();
        options.into_iter().for_each(|x| vec.push(*x));
        IPV4Header::calculate_checksum(&mut vec);

        vec
    }

    fn calculate_checksum(buf: &mut [u8]) {
        let mut sum = 0u32;
        let chunks = buf.chunks_exact(2);
        for chunk in chunks {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        let mut remainder = (sum >> 16);
        while remainder != 0 {
            sum += remainder;
            remainder = (sum >> 16);
        }

        buf[10..12].copy_from_slice(&u16::to_be_bytes(!(sum as u16)));
    }
}
