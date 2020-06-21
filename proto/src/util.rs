use std::io;
use std::process::{Command, ExitStatus};
use std::fs::File;
use std::io::{BufWriter, Write};
use byteorder::WriteBytesExt;

pub fn cmd(cmd: &str, args: Vec<&str>) -> Result<ExitStatus, io::Error> {
    Command::new(cmd)
        .args(&args)
        .spawn()
        .unwrap()
        .wait()
}

pub fn disable_ipv4_forward() {
    let file = File::open("//proc/sys/net/ipv4/ip_forward").unwrap();
    let mut writer = BufWriter::new(file);
    writer.write("0".as_bytes()).unwrap();
    drop(writer);
}