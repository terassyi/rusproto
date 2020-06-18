use nix::fcntl;
use nix::sys::stat;
use nix::unistd::{read, write, close};
use std::io;
use std::os::unix::io::RawFd;
use std::os::unix::io::AsRawFd;
use crate::device::Device;

#[derive(Debug)]
pub struct BpfDevice {
    fd: RawFd,
}

impl AsRawFd for BpfDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl BpfDevice {
    pub fn new(_name: &str) -> io::Result<BpfDevice>{
        Ok(BpfDevice {
            fd: open_bpf_device()?,
        })
    }
}

fn open_bpf_device() -> io::Result<RawFd> {
    for i in 0..256 {
        let dev = &format!("/dev/bpf{}", i);
        match fcntl::open::<str>(dev, fcntl::OFlag::O_RDWR|fcntl::OFlag::O_NONBLOCK, stat::Mode::empty()) {
            Ok(fd) => return Ok(fd),
            Err(_) => continue,
        }
    };
    Err(io::Error::last_os_error())
}

impl Device for BpfDevice {
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

impl Drop for BpfDevice {
    fn drop(&mut self){
        close(self.fd);
    }
}

#[cfg(test)]
mod tests {
    use crate::device::Device;

    #[test]
    fn test_open_bpf_device() {
        assert_ne!(super::open_bpf_device().unwrap(), -1);
    }
    // #[test]
    // fn test_bpf_recv() {
    //     let mut buf = [0u8; 256];
    //     let dev = super::BpfDevice::new("test").unwrap();
    //     let l = dev.recv(&mut buf.as_mut()).unwrap();
    //     println!("{:?}", buf.to_vec());
    //     assert_ne!(l, 0);
    // }
}