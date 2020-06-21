
use super::ethernet::EtherType as ProtocolType;
use byteorder::{BigEndian, ByteOrder};
use crate::packet::error::{Error, ErrorKind};

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
pub enum HardwareType {
    Ethernet = 1,
    Unknown
}

impl HardwareType {
    fn addr_len(&self) -> usize {
        match self {
            &HardwareType::Ethernet => 6,
            &HardwareType::Unknown => 0,
        }
    }
}

impl std::convert::From<u16> for HardwareType {
    fn from(typ: u16) -> Self {
        match typ {
            1 => HardwareType::Ethernet,
            _ => HardwareType::Unknown
        }
    }
}

impl std::convert::From<HardwareType> for u16 {
    fn from(typ: HardwareType) -> u16 {
        match typ {
            HardwareType::Ethernet => 1,
            HardwareType::Unknown => 0,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
pub enum Operation {
    Request = 1,
    Reply = 2,
    Unknown
}

impl std::convert::From<u16> for Operation {
    fn from(op: u16) -> Operation {
        match op {
            1 => Operation::Request,
            2 => Operation::Reply,
            _ => Operation::Unknown
        }
    }
}

impl std::convert::From<Operation> for u16 {
    fn from(op: Operation) -> u16 {
        match op {
            Operation::Request => 1,
            Operation::Reply => 2,
            Operation::Unknown => 0,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Packet {
    buffer: Vec<u8>
}

mod field {
    use std::ops::Range;

    pub const HTYPE: Range<usize> = 0..2;
    pub const PTYPE: Range<usize> = 2..4;
    pub const HLEN: usize = 4;
    pub const PLEN: usize = 5;
    pub const OPER: Range<usize> = 6..8;

    // arp body format
    #[inline]
    pub fn SHA(hlen: usize, _plen: usize) -> Range<usize> {
        OPER.end..(hlen+OPER.end)
    }
    #[inline]
    pub fn SPA(hlen: usize, plen: usize) -> Range<usize> {
        let start = SHA(hlen, plen).end;
        start..(start+plen)
    }
    #[inline]
    pub fn THA(hlen: usize, plen: usize) -> Range<usize> {
        let start = SPA(hlen, plen).end;
        start..(start+hlen)
    }
    #[inline]
    pub fn TPA(hlen: usize, plen: usize) -> Range<usize> {
        let start = THA(hlen, plen).end;
        start..(start+plen)
    }
}

impl Packet {
    pub fn new(buffer: Vec<u8>) -> Result<Self, Error> {
        let p = Packet { buffer };
        p.is_valid()?;
        Ok(p)
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    fn is_valid(&self) -> Result<(), Error> {
        let l = self.len();
        if l < field::OPER.end {
            return Err(Error::from(ErrorKind::InvalidFormat))
        } else if l < field::TPA(self.hlen(), self.plen()).end {
            return Err(Error::from(ErrorKind::InvalidFormat))
        }
        Ok(())
    }

    pub fn into_buffer(self) -> Vec<u8> {
        self.buffer
    }

    pub fn htype(&self) -> HardwareType {
        let buf = self.buffer.as_slice();
        let typ = BigEndian::read_u16(&buf[field::HTYPE]);
        HardwareType::from(typ)
    }

    pub fn ptype(&self) -> ProtocolType {
        let buf = self.buffer.as_slice();
        let typ = BigEndian::read_u16(&buf[field::PTYPE]);
        ProtocolType::from(typ)
    }

    pub fn hlen(&self) -> usize {
        let buf = self.buffer.as_slice();
        buf[field::HLEN] as usize
    }

    pub fn plen(&self) -> usize {
        let buf = self.buffer.as_slice();
        buf[field::PLEN] as usize
    }

    pub fn operation(&self) -> Operation {
        let buf = self.buffer.as_slice();
        let op = BigEndian::read_u16(&buf[field::OPER]);
        Operation::from(op)
    }

    pub fn source_hardware_addr(&self) -> &[u8] {
        let buf = self.buffer.as_slice();
        &buf[field::SHA(self.hlen(), self.plen())]
    }

    pub fn source_protocol_addr(&self) -> &[u8] {
        let buf = self.buffer.as_slice();
        &buf[field::SPA(self.hlen(), self.plen())]
    }

    pub fn target_hardware_addr(&self) -> &[u8] {
        let buf = self.buffer.as_slice();
        &buf[field::THA(self.hlen(), self.plen())]
    }

    pub fn target_protocol_addr(&self) -> &[u8] {
        let buf = self.buffer.as_slice();
        &buf[field::TPA(self.hlen(), self.plen())]
    }

    // setter
    pub fn with_type(htype: HardwareType, ptype: ProtocolType) -> Result<Self, Error> {
        let mut buf = vec![0u8; field::OPER.end+ 2*(htype.addr_len()+ptype.addr_len())];
        buf[field::HLEN] = htype.addr_len() as u8;
        buf[field::PLEN] = ptype.addr_len() as u8;
        BigEndian::write_u16(&mut buf[field::HTYPE], htype.into());
        BigEndian::write_u16(&mut buf[field::PTYPE], ptype.into());
        Packet::new(buf)
    }

    pub fn set_op(&mut self, op: Operation) {
        let buf = self.buffer.as_mut_slice();
        BigEndian::write_u16(&mut buf[field::OPER], op.into())
    }

    pub fn set_source_hardware_addr(&mut self, src: &[u8]) {
        let (hlen, plen) = (self.hlen(), self.plen());
        let buf = self.buffer.as_mut_slice();
        buf[field::SHA(hlen, plen)].copy_from_slice(src)
    }

    pub fn set_source_protocol_addr(&mut self, src: &[u8]) {
        let (hlen, plen) = (self.hlen(), self.plen());
        let buf = self.buffer.as_mut_slice();
        buf[field::SPA(hlen, plen)].copy_from_slice(src)
    }

    pub fn set_target_hardware_addr(&mut self, target: &[u8]) {
        let (hlen, plen) = (self.hlen(), self.plen());
        let buf = self.buffer.as_mut_slice();
        buf[field::THA(hlen, plen)].copy_from_slice(target)
    }

    pub fn set_target_protocol_addr(&mut self, target: &[u8]) {
        let (hlen, plen) = (self.hlen(), self.plen());
        let buf = self.buffer.as_mut_slice();
        buf[field::TPA(hlen, plen)].copy_from_slice(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd::SysconfVar::OPEN_MAX;
    use crate::packet::ethernet::MACAddress;

    static PACKET_BYTES: [u8; 28] =
        [0x00, 0x01,
            0x08, 0x00,
            0x06,
            0x04,
            0x00, 0x01,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x21, 0x22, 0x23, 0x24,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
            0x41, 0x42, 0x43, 0x44];

    #[test]
    fn test_htype() {
        let p = Packet::new(PACKET_BYTES.to_vec()).unwrap();
        assert_eq!(p.htype(), HardwareType::Ethernet);
    }
    #[test]
    fn test_op() {
        let p = Packet::new(PACKET_BYTES.to_vec()).unwrap();
        assert_eq!(p.operation(), Operation::Request);
    }
    #[test]
    fn test_source_hardware_addr() {
        let p = Packet::new(PACKET_BYTES.to_vec()).unwrap();
        assert_eq!(p.source_hardware_addr(), &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16])
    }
    #[test]
    fn test_with_type() {
        let p = Packet::with_type(HardwareType::Ethernet, ProtocolType::Ipv4).unwrap();
        assert_eq!(p.hlen(), 6);
        assert_eq!(p.plen(), 4);
        assert_eq!(p.htype(), HardwareType::Ethernet);
        assert_eq!(p.ptype(), ProtocolType::Ipv4);
        assert_eq!(p.source_protocol_addr(), &[0,0,0,0]);
    }
    #[test]
    fn test_set_source_hardware_addr() {
        let mut p = Packet::with_type(HardwareType::Ethernet, ProtocolType::Ipv4).unwrap();
        p.set_source_hardware_addr(MACAddress::BROADCAST.as_bytes());
        assert_eq!(p.hlen(), 6);
        assert_eq!(p.plen(), 4);
        assert_eq!(p.htype(), HardwareType::Ethernet);
        assert_eq!(p.ptype(), ProtocolType::Ipv4);
        assert_eq!(p.source_protocol_addr(), &[0,0,0,0]);
        assert_eq!(p.source_hardware_addr(), MACAddress::BROADCAST.as_bytes())
    }
}