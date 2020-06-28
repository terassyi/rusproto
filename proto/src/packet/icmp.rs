use crate::packet::icmp::Type::EchoRequest;
use std::fmt;
use std::intrinsics::write_bytes;
use std::fmt::Debug;
use crate::packet::error::Error;
use byteorder::{BigEndian, ByteOrder};

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
pub enum Type {
    EchoReply = 0,
    DstUnreachable = 3,
    SourceQuench = 4,
    Redirect = 5,
    EchoRequest = 8,
    RouterAdvertisement = 9,
    RouterSolicitation = 10,
    TimeExceeded = 11,
    ParameterProblem = 12,
    Timestamp = 13,
    TimestampReply = 14,
    InformationRequest = 15,
    InformationReply = 16,
    AddressMaskRequest = 17,
    AddressMaskReply = 18,
    Unknown
}

impl std::convert::From<u8> for Type {
    fn from(t: u8) -> Type {
        match t {
            0 => Type::EchoReply,
            3 => Type::DstUnreachable,
            4 => Type::SourceQuench,
            5 => Type::Redirect,
            8 => Type::EchoRequest,
            9 => Type::RouterAdvertisement,
            10 => Type::RouterSolicitation,
            11 => Type::TimeExceeded,
            12 => Type::ParameterProblem,
            13 => Type::Timestamp,
            14 => Type::TimestampReply,
            15 => Type::InformationRequest,
            16 => Type::InformationReply,
            17 => Type::AddressMaskRequest,
            18 => Type::AddressMaskReply,
            _ => Type::Unknown
        }
    }
}

impl std::convert::From<Type> for u8 {
    fn from(t: Type) -> u8 {
        match t {
            Type::EchoReply => 0,
            Type::DstUnreachable => 3,
            Type::SourceQuench => 4,
            Type::Redirect => 5,
            Type::EchoRequest => 8,
            Type::RouterAdvertisement => 9,
            Type::RouterSolicitation => 10,
            Type::TimeExceeded => 11,
            Type::ParameterProblem => 12,
            Type::Timestamp => 13,
            Type::TimestampReply => 14,
            Type::InformationRequest => 15,
            Type::InformationReply => 16,
            Type::AddressMaskRequest => 17,
            Type::AddressMaskReply => 18,
            Type::Unknown => 0xff,
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Type::EchoReply => write!(f, "echo reply"),
            &Type::DstUnreachable => write!(f, "destination unreachable"),
            &Type::SourceQuench => write!(f, "source quench"),
            &Type::Redirect => write!(f, "redirect"),
            &Type::EchoRequest => write!(f, "echo request"),
            &Type::RouterAdvertisement => write!(f, "router advertisement"),
            &Type::RouterSolicitation => write!(f, "router solicitaion"),
            &Type::TimeExceeded => write!(f, "time exceeded"),
            &Type::ParameterProblem => write!(f, "parameter problem"),
            &Type::Timestamp => write!(f, "timestamp"),
            &Type::TimestampReply => write!(f, "timestamp reply"),
            &Type::InformationRequest => write!(f, "information request"),
            &Type::InformationReply => write!(f, "information reply"),
            &Type::AddressMaskRequest => write!(f, "address mask request"),
            &Type::AddressMaskReply => write!(f, "address mask reply"),
            &Type::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum DstUnreachableCode {
    NetworkUnreachable = 0,
    HostUnreachable = 1,
    ProtocolUnreachable = 2,
    PortUnreachable = 3,
    FragmentRequired = 4,
    SrcRoutingFailed = 5,
    Unknown
}

impl std::convert::From<u8> for DstUnreachableCode {
    fn from(c: u8) -> DstUnreachableCode {
        match c {
            0 => DstUnreachableCode::NetworkUnreachable,
            1 => DstUnreachableCode::HostUnreachable,
            2 => DstUnreachableCode::ProtocolUnreachable,
            3 => DstUnreachableCode::PortUnreachable,
            4 => DstUnreachableCode::FragmentRequired,
            5 => DstUnreachableCode::SrcRoutingFailed,
            _ => DstUnreachableCode::Unknown
        }
    }
}

impl std::convert::From<DstUnreachableCode> for u8 {
    fn from(c: DstUnreachableCode) -> u8 {
        match c {
            DstUnreachableCode::NetworkUnreachable => 0,
            DstUnreachableCode::HostUnreachable => 1,
            DstUnreachableCode::ProtocolUnreachable => 2,
            DstUnreachableCode::PortUnreachable => 3,
            DstUnreachableCode::FragmentRequired => 4,
            DstUnreachableCode::SrcRoutingFailed => 5,
            DstUnreachableCode::Unknown => 0xff
        }
    }
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct Packet {
    buffer: Vec<u8>
}

mod field {
    use std::ops::{Range, RangeFrom};

    pub const TYPE: usize = 0;
    pub const CODE: usize = 1;
    pub const CHECKSUM: Range<usize> = 2..4;
    pub const DATA: RangeFrom<usize> = 4..;

    pub mod echo {
        use std::ops::{Range, RangeFrom};

        pub const IDENT: Range<usize> = 4..6;
        pub const SEQNO: Range<usize> = 6..8;
        pub const DATA: RangeFrom<usize> = 8..;
    }

    pub mod unreachable {
        use std::ops::{Range, RangeFrom};

        pub const UNUSED: Range<usize> = 4..6;
        pub const NEXT: Range<usize> = 6..8;
        pub const DATA: RangeFrom<usize> = 8..;
    }
}

pub mod checksum {
    use std::io::Cursor;
    use byteorder::{ReadBytesExt, BigEndian};

    pub fn calc(mut data: &[u8]) -> u16 {
        let mut res: u32 = 0xffffu32;
        let mut buffer = Cursor::new(data);
        while let Ok(val) = buffer.read_u16::<BigEndian>() {
            if buffer.position() == 4 {
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
        Ok(Packet{buffer})
    }

    pub fn header(&self) -> &[u8] {
        let b = self.buffer.as_slice();
        &b[0..field::DATA.start]
    }

    pub fn typ(&self) -> Type {
        let b = self.buffer.as_slice();
        Type::from(b[field::TYPE])
    }

    pub fn code(&self) -> u8 {
        let b = self.buffer.as_slice();
        b[field::CODE]
    }

    pub fn checksum(&self) -> u16 {
        let b = self.buffer.as_slice();
        BigEndian::read_u16(&b[field::CHECKSUM])
    }

    pub fn data(&self) -> &[u8] {
        let b = self.buffer.as_slice();
        &b[field::DATA]
    }

    pub fn echo_ident(&self) -> Option<u16> {
        let b = self.buffer.as_slice();
        match self.typ() {
            Type::EchoReply => Some(BigEndian::read_u16(&b[field::echo::IDENT])),
            Type::EchoRequest => Some(BigEndian::read_u16(&b[field::echo::IDENT])),
            _ => None
        }
    }

    pub fn echo_seqno(&self) -> Option<u16> {
        let b = self.buffer.as_slice();
        match self.typ() {
            Type::EchoReply => Some(BigEndian::read_u16(&b[field::echo::SEQNO])),
            Type::EchoRequest => Some(BigEndian::read_u16(&b[field::echo::SEQNO])),
            _ => None
        }
    }

    pub fn echo_data(&self) -> Option<&[u8]> {
        let b = self.buffer.as_slice();
        match self.typ() {
            Type::EchoReply => Some(&b[field::echo::DATA]),
            Type::EchoRequest => Some(&b[field::echo::DATA]),
            _ => None
        }
    }

    pub fn unreachable_code(&self) -> Option<DstUnreachableCode> {
        let b = self.buffer.as_slice();
        match self.typ() {
            Type::DstUnreachable => Some(DstUnreachableCode::from(b[field::CODE])),
            _ => None,
        }
    }

    pub fn unreachable_nexthop(&self) -> Option<u16> {
        let b = self.buffer.as_slice();
        match self.typ() {
            Type::DstUnreachable => Some(BigEndian::read_u16(&b[field::unreachable::NEXT])),
            _ => None,
        }
    }

    pub fn unreachable_data(&self) -> Option<&[u8]> {
        let b = self.buffer.as_slice();
        match self.typ() {
            Type::DstUnreachable => Some(&b[field::unreachable::DATA]),
            _ => None
        }
    }

    // setter
    pub fn set_type(&mut self, typ: Type) {
        let mut b = self.buffer.as_mut_slice();
        let v: u8 = typ.into();
        b[field::TYPE] = v;
    }

    pub fn set_code(&mut self, code: u8) {
        let mut b = self.buffer.as_mut_slice();
        b[field::CODE] = code;
    }

    pub fn set_checksum(&mut self, sum: u16) {
        let mut b = self.buffer.as_mut_slice();
        BigEndian::write_u16(&mut b[field::CHECKSUM], sum);
    }

    pub fn set_data(&mut self, data: &[u8]) {
        let mut b = self.buffer.as_mut_slice();
        b[field::DATA].copy_from_slice(data);
    }

    pub fn set_echo_ident(&mut self, ident: u16) {
        let mut b = self.buffer.as_mut_slice();
        BigEndian::write_u16(&mut b[field::echo::IDENT], ident);
    }

    pub fn set_echo_seqno(&mut self, no: u16) {
        let mut b = self.buffer.as_mut_slice();
        BigEndian::write_u16(&mut b[field::echo::SEQNO], no);
    }

    pub fn set_echo_data(&mut self, data: &[u8]) {
        let mut b = self.buffer.as_mut_slice();
        b[field::echo::DATA].copy_from_slice(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static ECHO_PACKET_BYTES: [u8; 12] =
        [0x08, 0x00, 0x8e, 0xfe,
            0x12, 0x34, 0xab, 0xcd,
            0xaa, 0x00, 0x00, 0xff];

    static ECHO_DATA_BYTES: [u8; 4] =
        [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_icmp_packet() {
        let p = Packet::new(ECHO_PACKET_BYTES.to_vec()).unwrap();
        assert_eq!(p.typ(), Type::EchoRequest);
        assert_eq!(p.code(), 0);
        assert_eq!(p.checksum(), 0x8efe);
        assert_eq!(p.echo_ident().unwrap(), 0x1234);
        assert_eq!(p.echo_seqno().unwrap(), 0xabcd);
        assert_eq!(p.echo_data().unwrap(), &[0xaa, 0x00, 0x00, 0xff]);
        assert_eq!(p.header(), &[0x08, 0x00, 0x8e, 0xfe])
    }
    #[test]
    fn test_icmp_build_packet() {

        let mut p = Packet::new(vec![0u8;12]).unwrap();
        p.set_type(Type::EchoRequest);
        p.set_code(0);
        p.set_echo_ident(0x1234);
        p.set_echo_seqno(0xabcd);
        p.set_echo_data(&ECHO_DATA_BYTES);
        p.set_checksum(checksum::calc(p.buffer.as_slice()));
        assert_eq!(p.typ(), Type::EchoRequest);
        assert_eq!(p.code(), 0);
        assert_eq!(p.checksum(), 0x8efe);
        assert_eq!(p.echo_ident().unwrap(), 0x1234);
        assert_eq!(p.echo_seqno().unwrap(), 0xabcd);
        assert_eq!(p.echo_data().unwrap(), &[0xaa, 0x00, 0x00, 0xff]);
        assert_eq!(p.header(), &[0x08, 0x00, 0x8e, 0xfe])
    }
    #[test]
    fn test_calc_icmp_checksum() {
        let p = Packet::new(ECHO_PACKET_BYTES.to_vec()).unwrap();
        let sum = checksum::calc(p.buffer.as_slice());
        assert_eq!(sum, 0x8efe);
    }
}