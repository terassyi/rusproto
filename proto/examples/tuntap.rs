
use proto;
use proto::device::Device;

use proto::util;

fn main() {
    let mut name = String::from("exp0");
    let mut dev = proto::device::tuntap::TapDevice::new(name.as_mut_str()).unwrap();
    // dev.setup().unwrap();
    // dev.up().unwrap();
    println!("{:?}", dev);

    util::cmd("ip", vec!["addr", "add", "192.168.100.20/24", "dev", "exp0"]).unwrap();
    util::cmd("ip", vec!["link", "set", "up", "dev", "exp0"]).unwrap();

    loop {
        let mut buf = [0u8;256];
        let len = dev.recv(&mut buf).unwrap();
        println!("[info] received {} bytes", len);
        println!("{:?}", buf.to_vec());
    }
}