use std::io;
use nix::sys::socket;
use std::os::unix::io::RawFd;
use std::os::unix::io::AsRawFd;
use crate::device::{Device, ifreq};
use nix::unistd::{read, write};

pub struct RawSocketDevice {
    fd: RawFd,
    ifreq: ifreq,
}

impl AsRawFd for RawSocketDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl RawSocketDevice {
    pub fn new(name: &str) -> io::Result<RawSocketDevice> {
        let soc = unsafe {
            let lower = libc::socket(libc::AF_PACKET, libc::SOCK_RAW,
                                     libc::ETH_P_ALL);
            if lower == -1 { return Err(io::Error::last_os_error()) }
            lower
        };
        Ok(RawSocketDevice{
            fd: soc,
            ifreq: ifreq_for(name),
        })
    }
}

impl Device for RawSocketDevice {
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

#[cfg(test)]
mod tests {
    #[test]
    fn test_new_raw_socket() {
        let dev = super::RawSocketDevice::new("test").unwrap();
        assert_ne!(dev.fd, -1);
    }
}