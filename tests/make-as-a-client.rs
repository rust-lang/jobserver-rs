extern crate jobserver;
extern crate tempdir;

use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::net::{TcpStream, TcpListener};
use std::process::Command;

use jobserver::Client;
use tempdir::TempDir;

macro_rules! t {
    ($e:expr) => (match $e {
        Ok(e) => e,
        Err(e) => panic!("{} failed with {}", stringify!($e), e),
    })
}

fn main() {
    if let Ok(s) = env::var("TEST_ADDR") {
        let mut contents = Vec::new();
        t!(t!(TcpStream::connect(&s)).read_to_end(&mut contents));
        return
    }

    let c = t!(Client::new(1));
    let td = TempDir::new("foo").unwrap();

    let prog = env::var("MAKE").unwrap_or("make".to_string());
    let mut cmd = Command::new(prog);
    cmd.current_dir(td.path());

    let me = t!(env::current_exe());
    let me = me.to_str().unwrap();
    t!(t!(File::create(td.path().join("Makefile"))).write_all(format!("\
all: foo bar
foo:
\t{0}
bar:
\t{0}
", me).as_bytes()));

    // We're leaking one extra token to `make` sort of violating the makefile
    // jobserver protocol. It has the desired effect though.
    c.configure(&mut cmd);

    let listener = t!(TcpListener::bind("127.0.0.1:0"));
    let addr = t!(listener.local_addr());
    cmd.env("TEST_ADDR", addr.to_string());
    let mut child = t!(cmd.spawn());

    // We should get both connections as the two programs should be run
    // concurrently.
    let a = t!(listener.accept());
    let b = t!(listener.accept());
    drop((a, b));

    assert!(t!(child.wait()).success());
}

