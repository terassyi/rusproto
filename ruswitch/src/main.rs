extern crate proto;
use proto::device::Device;
use proto::device::tuntap::TapDevice;
use proto::util;

fn main() {
    let (dev0, dev1) = setup();
    loop {
        let mut buf0 = [0u8; 256];
        let len = dev0.recv(&mut buf0).unwrap();
        println!("[info] ({:?}) recieve {:?} bytes", dev0.name(), len);
        let len = dev1.send(&mut buf0).unwrap();
    }
}

fn setup() -> (TapDevice, TapDevice) {
    let mut name0 = String::from("dev0");
    let mut name1 = String::from("dev1");
    let dev0 = TapDevice::new(&mut name0).unwrap();
    let dev1 = TapDevice::new(&mut name1).unwrap();

    util::cmd("ip", vec!["link", "set", "up", "dev", "dev0"]).unwrap();
    util::cmd("ip", vec!["addr", "add", "192.168.100.20/24", "dev", "dev0"]).unwrap();
    util::cmd("ip", vec!["link", "set", "up", "dev", "dev1"]).unwrap();
    util::cmd("ip", vec!["addr", "add", "192.168.100.21/24", "dev", "dev1"]).unwrap();

    (dev0, dev1)
}
