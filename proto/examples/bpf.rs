
// extern crate proto;

use proto;
use proto::device::Device;

fn main() {
    let dev = proto::device::bpf::BpfDevice::new("exp0").unwrap();
    loop {
        let mut buf = [0u8;256];
        let len = dev.recv(&mut buf).unwrap();
        println!("{:?}", String::from_utf8(buf.to_vec()));
    }
}