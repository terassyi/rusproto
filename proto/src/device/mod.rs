use std::io;
use std::os::raw::c_char;
use libc;

pub mod bpf;
pub mod tuntap;
pub mod raw_socket;

pub trait Device {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn send(&self, buf: &[u8]) -> io::Result<usize>;
}

#[derive(Debug)]
pub struct ifreq {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    ifr_flags: libc::c_int,
}