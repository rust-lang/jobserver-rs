use std::env;
use std::io::prelude::*;
use std::io::BufReader;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;

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
    cmd.env("I_AM_THE_CLIENT", "1").stdout(Stdio::piped());

    let acq = client.acquire().unwrap();
    let mut child = client
        .configure_and_run(&mut cmd, |cmd| cmd.spawn())
        .unwrap();

    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let t = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            tx.send(line.unwrap()).unwrap();
        }
    });

    for _ in 0..100 {
        assert!(rx.try_recv().is_err());
    }

    drop(acq);
    assert_eq!(rx.recv().unwrap(), "hello!");
    t.join().unwrap();
    assert!(rx.recv().is_err());
    client.acquire().unwrap();
}

fn client() {
    let client = unsafe { Client::from_env().unwrap() };
    let acq = client.acquire().unwrap();
    println!("hello!");
    drop(acq);
}
