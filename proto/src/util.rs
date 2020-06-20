use std::io;
use std::process::{Command, ExitStatus};

pub fn cmd(cmd: &str, args: Vec<&str>) -> Result<ExitStatus, io::Error> {
    Command::new(cmd)
        .args(&args)
        .spawn()
        .unwrap()
        .wait()
}