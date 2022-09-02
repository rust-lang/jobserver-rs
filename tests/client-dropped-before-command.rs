use std::env;
use std::process::{Command, Output};

use jobslot::Client;

fn main() {
    if env::var("I_AM_THE_CLIENT").is_ok() {
        client();
    } else {
        server();
    }
}

fn server() {
    let me = env::current_exe().unwrap();
    let client = Client::new(1).unwrap();

    let mut cmd = Command::new(me);
    cmd.env("I_AM_THE_CLIENT", "1");

    let Output {
        status,
        stdout: _stdout,
        stderr,
    } = client
        .configure_and_run(&mut cmd, |cmd| cmd.output())
        .unwrap();

    assert!(status.success(), "{:#?}", String::from_utf8_lossy(&stderr));
    assert_eq!(&*stderr, b"hello!\n");
}

fn client() {
    let client = unsafe { Client::from_env().unwrap() };
    let acq = client.acquire().unwrap();
    eprintln!("hello!");
    drop(acq);
}
