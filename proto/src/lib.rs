pub mod device;
pub mod ethernet;
pub mod util;
pub mod packet;

extern crate pnet;
extern crate pnet_datalink;
extern crate nix;
extern crate byteorder;
extern crate thiserror;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
