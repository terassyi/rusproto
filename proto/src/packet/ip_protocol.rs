
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
pub enum IpProtocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    Unknown,
}

impl std::convert::From<u8> for IpProtocol {
    fn from(p: u8) -> IpProtocol {
        match p {
            1 => IpProtocol::ICMP,
            6 => IpProtocol::TCP,
            17 => IpProtocol::UDP,
            _ => IpProtocol::Unknown
        }
    }
}

impl std::convert::From<IpProtocol> for u8 {
    fn from(p: IpProtocol) -> u8 {
        match p {
            IpProtocol::ICMP => 1,
            IpProtocol::TCP => 6,
            IpProtocol::UDP => 17,
            IpProtocol::Unknown => 0,
        }
    }
}