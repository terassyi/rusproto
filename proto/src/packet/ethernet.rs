use std::fmt;
use {Result};
use byteorder::{BigEndian, ByteOrder};
use std::fmt::Display;

// ethernet frame
#[derive(Debug)]
pub struct Frame {
    buffer: Vec<u8>
}

mod field {
    use std::ops::{Range, RangeFrom};

    pub const DST: Range<usize> = 0..6;
    pub const SRC: Range<usize> = 6..12;
    pub const TYP: Range<usize> = 12..14;
    pub const PAYLOAD: RangeFrom<usize> = 14..;
}

// impl fmt::Display for Frame {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//     }
// }

impl Frame {
    pub fn new(buffer: Vec<u8>) -> Self {
        Frame {
            buffer
        }
    }

    // getter
    pub fn dst(&self) -> MACAddress {
        let buf = self.buffer.as_slice();
        MACAddress::from_bytes(&buf[field::DST])
    }

    pub fn src(&self) -> MACAddress {
        let buf = self.buffer.as_slice();
        MACAddress::from_bytes(&buf[field::SRC])
    }

    pub fn ethertype(&self) -> EtherType {
        let buf = self.buffer.as_slice();
        let typ = BigEndian::read_u16(&buf[field::TYP]);
        match typ {
            0x0800 => EtherType::Ipv4,
            0x0806 => EtherType::Ipv6,
            0x86dd => EtherType::Arp,
            _ => EtherType::UNKNOWN
        }
    }

    pub fn payload(&self) -> &[u8] {
        let buf = self.buffer.as_slice();
        &buf[field::PAYLOAD]
    }

    pub fn mut_payload(&mut self) -> &mut [u8] {
        let buf = self.buffer.as_mut_slice();
        &mut buf[field::PAYLOAD]
    }

    // setter
    pub fn set_dst(&mut self, dst: MACAddress) {
        let buf = self.buffer.as_mut_slice();
        buf[field::DST].copy_from_slice(dst.as_bytes())
    }

    pub fn set_src(&mut self, src: MACAddress) {
        let buf = self.buffer.as_mut_slice();
        buf[field::SRC].copy_from_slice(src.as_bytes())
    }

    pub fn set_type(&mut self, typ: EtherType) {
        let buf = self.buffer.as_mut_slice();
        BigEndian::write_u16(&mut buf[field::TYP], typ.into())
    }

    pub fn set_payload(&mut self, payload: &[u8]) {
        let buf = self.buffer.as_mut_slice();
        buf[field::PAYLOAD].copy_from_slice(payload)
    }

    // fotmatter
    pub fn log(&self) {
        println!("dst={:?}", self.dst());
        println!("src={:?}", self.src());
        println!("typ={:?}", self.ethertype());
        // println!("{:?}", self.payload());
    }
}

// ether type definition
#[derive(Eq, PartialEq)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Ipv6 = 0x0806,
    Arp = 0x86dd,
    UNKNOWN,
}

impl fmt::Debug for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &EtherType::Ipv4 => write!(f, "IPv4"),
            &EtherType::Ipv6 => write!(f, "IPv6"),
            &EtherType::Arp => write!(f, "ARP"),
            &EtherType::UNKNOWN => write!(f, "UNKNOWN")
        }
    }
}

impl std::convert::From<u16> for EtherType {
    fn from(typ: u16) -> Self {
        match typ {
            0x0800 => EtherType::Ipv4,
            0x0806 => EtherType::Ipv6,
            0x86dd => EtherType::Arp,
            _ => EtherType::UNKNOWN
        }
    }
}

impl std::convert::From<EtherType> for u16 {
    fn from(typ: EtherType) -> Self {
        match typ {
            EtherType::Ipv4 => 0x0800,
            EtherType::Ipv6 => 0x0806,
            EtherType::Arp => 0x86dd,
            EtherType::UNKNOWN => 0x0000
        }
    }
}
// MAC Address definition
#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Default)]
pub struct MACAddress(pub [u8; 6]);

impl MACAddress {

    pub const BROADCAST: MACAddress = MACAddress([0xff; 6]);

    pub fn new(addr: [u8; 6]) -> Self {
        MACAddress(addr)
    }

    pub fn from_bytes(data: &[u8]) -> MACAddress {
        let mut addr = [0u8; 6];
        addr.copy_from_slice(data);
        MACAddress(addr)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_broadcast(&self) -> bool {
        *self == MACAddress::BROADCAST
    }
}

impl fmt::Debug for MACAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let b = self.as_bytes();
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3], b[4], b[5])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::ethernet::field::PAYLOAD;

    static FRAME_BYTES: [u8; 64] =
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x08, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00];

    static PAYLOAD_BYTES: [u8; 50] =
        [0x1, 0x1, 0x1, 0x1, 0x1, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0xff];

    #[test]
    fn test_set_dst() {
        let mut frame = Frame::new(FRAME_BYTES.to_vec());
        frame.set_dst(MACAddress::new(MACAddress::BROADCAST.0));
        assert_eq!(MACAddress::BROADCAST, frame.dst());
    }
    #[test]
    fn test_set_src() {
        let mut frame = Frame::new(FRAME_BYTES.to_vec());
        frame.set_src(MACAddress::new(MACAddress::BROADCAST.0));
        assert_eq!(MACAddress::BROADCAST, frame.src());
    }
    #[test]
    fn test_set_type() {
        let mut frame = Frame::new(FRAME_BYTES.to_vec());
        frame.set_type(EtherType::Arp);
        assert_eq!(EtherType::Arp, frame.ethertype());
    }
    #[test]
    fn test_set_payload() {
        let mut frame = Frame::new(FRAME_BYTES.to_vec());
        frame.set_payload(&PAYLOAD_BYTES);
        assert_eq!(frame.payload(), PAYLOAD_BYTES.as_ref());
    }
}