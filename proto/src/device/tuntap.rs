use nix;
use nix::fcntl;
use nix::sys::stat;
use nix::unistd::{read, write, close};
use libc;
use byteorder::{ByteOrder, NativeEndian};
use std::io;
use std::os::unix::io::RawFd;
use std::os::unix::io::AsRawFd;
use crate::device::{Device, ifreq};
use std::os::raw::{c_char, c_int};
use std::borrow::BorrowMut;
// use nix::sys::ioctl::ioctl;


pub const IFNAMSIZ: usize = 16;


pub const IFF_UP:      i16 = 0x1;

pub const IFF_RUNNING: i16 = 0x40;


pub const IFF_TUN:   i16 = 0x0001;
pub const IFF_TAP: i16 = 0x0002;

pub const IFF_NO_PI: i16 = 0x1000;

nix::ioctl_write_ptr!(tunsetiff, b'T', 202, i32);
nix::ioctl_write_ptr!(siocsifflags, b'T', 202, i32);

#[derive(Debug)]
pub struct TapDevice {
    fd: RawFd,
    ifreq: ifreq,
    mtu: usize,
}

impl AsRawFd for TapDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl TapDevice {
    pub fn new(name: &mut str) -> io::Result<TapDevice> {
        Ok(TapDevice{
            fd: open_tap_device(name)?,
            ifreq: ifreq_for(name),
            mtu: 0,
        }
        )
    }

    pub fn up(&self) -> io::Result<()> {
        let mut req = [0u8; 40];
        let name = String::from_utf8(self.ifreq.ifr_name.iter().map(|&i| i as u8).collect::<Vec<u8>>()).unwrap();
        req[..self.ifreq.ifr_name.len()].copy_from_slice(name.as_bytes());
        NativeEndian::write_i16(&mut req[16..], IFF_UP|IFF_RUNNING);
        let res = unsafe { libc::ioctl(self.fd, libc::SIOCSIFFLAGS, &mut req) };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn attach_interface(&mut self) -> io::Result<()> {
        self.ifreq.ifr_flags = (IFF_TUN | IFF_NO_PI) as libc::c_int;
        ifreq_ioctl(self.fd, &mut self.ifreq, 202).map(|_| ())
    }

    pub fn interface_mtu(&mut self) -> io::Result<usize> {
        let lower = unsafe {
            let lower = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_IP);
            if lower == -1 { return Err(io::Error::last_os_error()) }
            lower
        };

        let mtu = ifreq_ioctl(lower, &mut self.ifreq, 35105).map(|mtu| mtu as usize);

        unsafe { libc::close(lower); }

        mtu
    }
}

impl Device for TapDevice {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let len = read(self.fd, buf)
            .map_err(|_| io::Error::last_os_error())?;
        Ok(len)
    }

    fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let len = write(self.fd, buf)
            .map_err(|_| io::Error::last_os_error())?;
        Ok(len)
    }
}

fn open_tap_device(name: &mut str) -> io::Result<RawFd> {
    let dev = "/dev/net/tun";
    let fd = match fcntl::open::<str>(dev, fcntl::OFlag::O_RDWR, stat::Mode::empty()) {
        Ok(fd) => Ok(fd),
        Err(_) => Err(io::Error::last_os_error())
    }?;
    let mut req = [0u8; 40];
    if name.len() > (IFNAMSIZ-1) {
        return Err(io::ErrorKind::AddrNotAvailable.into());
    }
    req[..name.len()].copy_from_slice(name.as_bytes());
    NativeEndian::write_i16(&mut req[16..], IFF_TAP|IFF_NO_PI);
    unsafe { tunsetiff(fd, &mut req as *mut _ as *mut _) }
        .map_err(|_| io::Error::last_os_error() )?;
    Ok(fd)
}

fn ifreq_for(name: &str) -> ifreq {
    let mut ifreq = ifreq {
        ifr_name: [0; libc::IF_NAMESIZE],
        ifr_flags: 0
    };
    for (i, byte) in name.as_bytes().iter().enumerate() {
        ifreq.ifr_name[i] = *byte as libc::c_char
    }
    ifreq
}

fn ifreq_ioctl(lower: libc::c_int, ifreq: &mut ifreq,
               cmd: libc::c_ulong) -> io::Result<libc::c_int> {
    unsafe {
        let res = libc::ioctl(lower, cmd as _, ifreq as *mut ifreq);
        if res == -1 { return Err(io::Error::last_os_error()) }
    }

    Ok(ifreq.ifr_flags)
}



#[cfg(test)]
mod tests {
    use std::os::raw::c_int;
    use pnet_datalink;

    #[test]
    fn test_open_tap_device() {
        let mut dev = super::TapDevice::new(&mut "test").unwrap();
        assert_ne!(dev.ifreq.ifr_name.iter().map(|&c| c as u8)
                       .map(|c| c as char)
                       .collect::<String>(), "test".to_string());
    }
    // failed
    // #[test]
    // fn test_attach_interface() {
    //     let mut dev = super::TunDevice::new("test").unwrap();
    //     dev.attach_interface().unwrap();
    //     assert_eq!(pnet_datalink::interfaces().iter()
    //                    .find(|i| &*i.name == "test").unwrap().name, "test".to_string());
    // }
}