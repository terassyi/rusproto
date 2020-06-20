pub mod device;
mod ethernet;
pub mod util;

extern crate pnet;
extern crate pnet_datalink;
extern crate nix;
extern crate byteorder;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
