use crate::packet::error::Error;
use std::path::Prefix::Verbatim;
use byteorder::{BigEndian, ByteOrder};
use crate::packet::ip_protocol::IpProtocol;

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
pub struct IpAddress(pub [u8; 4]);

impl IpAddress {
    pub const BROADCAST: IpAddress = IpAddress([0xff, 0xff, 0xff, 0xff]);

    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        IpAddress([a, b, c, d])
    }

    pub fn from_bytes(addr: &[u8]) -> Self {
        let mut buf = [0u8 ;4];
        buf.copy_from_slice(addr);
        IpAddress(buf)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_broadcast(&self) -> bool {
        *self == IpAddress::BROADCAST
    }

    pub fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
pub enum Version {
    Ipv4 = 4,
    Unknown
}

impl std::convert::From<u8> for Version {
    fn from(v: u8) -> Version {
        match v {
            4 => Version::Ipv4,
            _ => Version::Unknown
        }
    }
}

impl std::convert::From<Version> for u8 {
    fn from(v: Version) -> u8 {
        match v {
            Version::Ipv4 => 4,
            Version::Unknown => 0,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
pub enum Flag {
    NoMore = 0,
    DontFragment = 2,
    MoreFragment = 4,
    Unknown
}

impl std::convert::From<u16> for Flag {
    fn from(f: u16) -> Flag {
        match f {
            0 => Flag::NoMore,
            2 => Flag::DontFragment,
            4 => Flag::MoreFragment,
            _ => Flag::Unknown
        }
    }
}

impl std::convert::From<Flag> for u16 {
    fn from(f: Flag) -> u16 {
        match f {
            Flag::NoMore => 0,
            Flag::DontFragment => 2,
            Flag::MoreFragment => 4,
            Flag::Unknown => 1 // invalid flag
        }
    }
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Packet {
    buffer: Vec<u8>
}

mod field {
    use std::ops::{Range, RangeFrom};

    pub const VERSION_IHL: usize = 0;
    pub const TOS: usize = 1;
    pub const LENGTH: Range<usize> = 2..4;
    pub const IDENT: Range<usize> = 4..6;
    pub const FLAG_OFFSET: Range<usize> = 6..8;
    pub const TTL: usize = 8;
    pub const PROTOCOL: usize = 9;
    pub const CHECKSUM: Range<usize> = 10..12;
    pub const SRC_ADDR: Range<usize> = 12..16;
    pub const DST_ADDR: Range<usize> = 16..20;

    pub fn OPTION(ihl: usize) -> Range<usize> {
        let start = DST_ADDR.end;
        start..(ihl*4)
    }

    pub fn PAYLOAD(ihl: usize, length: usize) -> Range<usize> {
        (ihl*4)..length
    }
}

pub mod checksum {
    use std::io::Cursor;
    use byteorder::{ReadBytesExt, BigEndian};

    pub fn calc(mut data: &[u8]) -> u16 {
        let mut res: u32 = 0xffffu32;
        let mut buffer = Cursor::new(data);
        while let Ok(val) = buffer.read_u16::<BigEndian>() {
            if buffer.position() == 12 {
                continue;
            }
            res += val as u32;
            if res > 0xffff {
                res -= 0xffff;
            }
        }
        !(res as u16)
    }
}

impl Packet {
    pub fn new(buffer: Vec<u8>) -> Result<Self, Error> {
        let p = Packet { buffer };
        Ok(p)
    }

    pub fn version(&self) -> Version {
        let b = self.buffer.as_slice();
        Version::from(b[field::VERSION_IHL] >> 4)
    }

    pub fn header_length(&self) -> usize {
        let b = self.buffer.as_slice();
        (b[field::VERSION_IHL] & 0x0f) as usize
    }

    pub fn tos(&self) -> u8 {
        let b = self.buffer.as_slice();
        b[field::TOS]
    }

    pub fn length(&self) -> usize {
        let b = self.buffer.as_slice();
        let l = BigEndian::read_u16(&b[field::LENGTH]);
        l as usize
    }

    pub fn identification(&self) -> u16 {
        let b = self.buffer.as_slice();
        BigEndian::read_u16(&b[field::IDENT])
    }

    pub fn flag(&self) -> Flag {
        let b = self.buffer.as_slice();
        let f = BigEndian::read_u16(&b[field::FLAG_OFFSET]) >> 13;
        println!("{:04x}", f<<13);
        Flag::from(f)
    }

    pub fn fragment(&self) -> u16 {
        let b = self.buffer.as_slice();
        BigEndian::read_u16(&b[field::FLAG_OFFSET]) & 0x1fff
    }

    pub fn ttl(&self) -> u8 {
        let b = self.buffer.as_slice();
        b[field::TTL]
    }

    pub fn protocol(&self) -> IpProtocol {
        let b = self.buffer.as_slice();
        IpProtocol::from(b[field::PROTOCOL])
    }

    pub fn checksum(&self) -> u16 {
        let b = self.buffer.as_slice();
        BigEndian::read_u16(&b[field::CHECKSUM])
    }

    pub fn verify_checksum(&self) -> bool {
        let checksum = self.checksum();
        checksum::calc(&mut self.header()) == checksum
    }

    pub fn source_addr(&self) -> IpAddress {
        let b = self.buffer.as_slice();
        IpAddress::from_bytes(&b[field::SRC_ADDR])
    }

    pub fn destination_addr(&self) -> IpAddress {
        let b = self.buffer.as_slice();
        IpAddress::from_bytes(&b[field::DST_ADDR])
    }

    pub fn option(&self) -> Vec<u8> {
        let b = self.buffer.as_slice();
        b[field::OPTION(self.header_length())].to_vec()
    }

    pub fn header(&self) -> &[u8] {
        let b = self.buffer.as_slice();
        &b[0..self.header_length()*4]
    }

    pub fn payload(&self) -> Vec<u8> {
        let b = self.buffer.as_slice();
        b[field::PAYLOAD(self.header_length(), self.length())].to_vec()
    }

    // setter
    pub fn set_version(&mut self, ver: Version) {
        let b = self.buffer.as_mut_slice();
        let v: u8 = ver.into();
        b[field::VERSION_IHL] = (b[field::VERSION_IHL] & 0x0f)  + (v << 4);
    }

    pub fn set_header_length(&mut self, ihl: usize) {
        let b = self.buffer.as_mut_slice();
        b[field::VERSION_IHL] = (b[field::VERSION_IHL] & 0xf0) + (ihl as u8 / 4);
    }

    pub fn set_tos(&mut self, tos: u8) {
        let b = self.buffer.as_mut_slice();
        b[field::TOS] = tos;
    }

    pub fn set_length(&mut self, length: usize) {
        let b = self.buffer.as_mut_slice();
        BigEndian::write_u16(&mut b[field::LENGTH], length as u16);
    }

    pub fn set_identification(&mut self, ident: u16) {
        let b = self.buffer.as_mut_slice();
        BigEndian::write_u16(&mut b[field::IDENT], ident);
    }

    pub fn set_flag(&mut self, flag: Flag) {
        let b = self.buffer.as_mut_slice();
        let s = BigEndian::read_u16(&b[field::FLAG_OFFSET]);
        let flag: u16 = flag.into();
        let f = (s & !0xe000) + flag << 13;
        BigEndian::write_u16(&mut b[field::FLAG_OFFSET], f);
    }

    pub fn set_fragment_offset(&mut self, offset: u16) {
        let b = self.buffer.as_mut_slice();
        let o = BigEndian::read_u16(&b[field::FLAG_OFFSET]);
        println!("{:04x}", o);
        let f = (o & 0xe000) + (offset >> 3);
        println!("{:04x}", f);
        BigEndian::write_u16(&mut b[field::FLAG_OFFSET], f);
    }

    pub fn set_ttl(&mut self, ttl: u8) {
        let b = self.buffer.as_mut_slice();
        b[field::TTL] = ttl;
    }

    pub fn set_protocol(&mut self, proto: IpProtocol) {
        let b = self.buffer.as_mut_slice();
        b[field::PROTOCOL] = proto.into();
    }

    pub fn set_checksum(&mut self, sum: u16) {
        let b = self.buffer.as_mut_slice();
        BigEndian::write_u16(&mut b[field::CHECKSUM], sum);
    }

    pub fn set_source_addr(&mut self, src: IpAddress) {
        let b = self.buffer.as_mut_slice();
        b[field::SRC_ADDR].copy_from_slice(src.as_bytes());
    }

    pub fn set_destination_addr(&mut self, dst: IpAddress) {
        let b = self.buffer.as_mut_slice();
        b[field::DST_ADDR].copy_from_slice(dst.as_bytes());
    }

    pub fn set_option(&mut self, option: &[u8]) {
        let ihl = self.header_length();
        let b = self.buffer.as_mut_slice();
        b[field::OPTION(ihl)].copy_from_slice(option);
    }

    pub fn set_payload(&mut self, payload: &[u8]) {
        let (ihl, length) = (self.header_length(), self.length());
        let b = self.buffer.as_mut_slice();
        b[field::PAYLOAD(ihl, length)].copy_from_slice(payload);
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_broadcast() {
        assert_eq!(IpAddress::new(255,255,255,255).is_broadcast(), true)
    }
    #[test]
    fn test_is_loopback() {
        assert_eq!(IpAddress::new(127,0,0,1).is_loopback(), true);
    }

    static PACKET_BYTES: [u8; 28] =
        [0x46, 0x00, 0x00, 0x1c,
            0x00, 0x00, 0x40, 0x00,
            0x40, 0x01, 0xd2, 0x79,
            0x11, 0x12, 0x13, 0x14,
            0x21, 0x22, 0x23, 0x24,
            0xff, 0xff, 0xff, 0xff,
            0xaa, 0x00, 0x00, 0xff];
    #[test]
    fn test_packet() {
        let p = Packet::new(PACKET_BYTES.to_vec()).unwrap();
        assert_eq!(p.version(), Version::Ipv4);
        assert_eq!(p.header_length(), 6);
        assert_eq!(p.tos(), 0);
        assert_eq!(p.length(), 0x1c);
        assert_eq!(p.identification(), 0);
        assert_eq!(p.flag(), Flag::DontFragment);
        assert_eq!(p.fragment(), 0);
        assert_eq!(p.ttl(), 0x40);
        assert_eq!(p.protocol(), IpProtocol::ICMP);
        assert_eq!(p.checksum(), 0xd279);
        assert_eq!(p.source_addr(), IpAddress::new(0x11,0x12,0x13,0x14));
        assert_eq!(p.destination_addr(), IpAddress::new(0x21,0x22,0x23,0x24));
        assert_eq!(p.option(), vec![0xff,0xff,0xff,0xff]);
        assert_eq!(p.payload(), vec![0xaa,0x00,0x00,0xff]);
    }
    #[test]
    fn test_build_ip_packet() {
        let mut p = Packet::new(vec![0u8;28]).unwrap();
        p.set_version(Version::Ipv4);
        p.set_header_length(24);
        p.set_tos(0);
        p.set_length(0x1c);
        p.set_identification(0);
        p.set_flag(Flag::DontFragment);
        p.set_fragment_offset(0);
        p.set_ttl(0x40);
        p.set_protocol(IpProtocol::ICMP);
        p.set_checksum(0xd279);
        p.set_source_addr(IpAddress::new(0x11,0x12,0x13,0x14));
        p.set_destination_addr(IpAddress::new(0x21,0x22,0x23,0x24));
        p.set_option(&[0xff;4]);
        p.set_payload(&[0xaa,0x00,0x00,0xff]);

        assert_eq!(p.version(), Version::Ipv4);
        assert_eq!(p.header_length(), 6);
        assert_eq!(p.tos(), 0);
        assert_eq!(p.length(), 0x1c);
        assert_eq!(p.identification(), 0);
        assert_eq!(p.flag(), Flag::DontFragment);
        assert_eq!(p.fragment(), 0);
        assert_eq!(p.ttl(), 0x40);
        assert_eq!(p.protocol(), IpProtocol::ICMP);
        assert_eq!(p.checksum(), 0xd279);
        assert_eq!(p.source_addr(), IpAddress::new(0x11,0x12,0x13,0x14));
        assert_eq!(p.destination_addr(), IpAddress::new(0x21,0x22,0x23,0x24));
        assert_eq!(p.option(), vec![0xff,0xff,0xff,0xff]);
        assert_eq!(p.payload(), vec![0xaa,0x00,0x00,0xff]);
    }
    #[test]
    fn test_ip_header() {
        let header: [u8; 24] =
            [0x46, 0x00, 0x00, 0x1c,
                0x00, 0x00, 0x40, 0x00,
                0x40, 0x01, 0xd2, 0x79,
                0x11, 0x12, 0x13, 0x14,
                0x21, 0x22, 0x23, 0x24,
                0xff, 0xff, 0xff, 0xff];
        let mut p = Packet::new(PACKET_BYTES.to_vec()).unwrap();
        assert_eq!(p.header(), &header);
    }
    static PACKET_HEADER: [u8; 20] =
        [0x45, 0x00, 0x00, 0x34,
            0x51, 0x25, 0x40, 0x00,
            0xff, 0x06, 0x08, 0x21,
            0x0a, 0x00, 0x0a, 0xbb,
            0x0a, 0x00, 0x03, 0xc3];
    #[test]
    fn test_build_checksum() {
        let sum = checksum::calc(&PACKET_HEADER);
        assert_eq!(sum, 0x0821);
    }
    #[test]
    fn test_verify_checksum() {
        let mut p = Packet::new(PACKET_BYTES.to_vec()).unwrap();
        assert_eq!(p.verify_checksum(), true)
    }
}