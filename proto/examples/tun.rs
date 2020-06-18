
use proto;
use proto::device::Device;

fn main() {
    let mut dev = proto::device::tun::TunDevice::new("exp0").unwrap();
    // dev.setup().unwrap();
    // dev.up().unwrap();
    loop {
        let mut buf = [0u8;256];
        let _len = dev.recv(&mut buf).unwrap();
        println!("{:?}", buf.to_vec());
    }
}