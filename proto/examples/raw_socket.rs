
use proto;
use proto::device::Device;

fn main() {
    let dev = proto::device::raw_socket::RawSocketDevice::new("exp0").unwrap();
    loop {
        let mut buf = [0u8; 256];
        let _len = dev.recv(&mut buf).unwrap();
        println!("{:?}", buf.to_vec());
    }
}