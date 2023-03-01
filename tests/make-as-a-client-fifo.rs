use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::net::{TcpListener, TcpStream};
use std::process::Command;

use jobslot::Client;

fn main() {
    if env::var("_DO_THE_TEST").is_ok() {
        std::process::exit(
            Command::new(env::var_os("MAKE").unwrap())
                .env("MAKEFLAGS", env::var_os("CARGO_MAKEFLAGS").unwrap())
                .env_remove("_DO_THE_TEST")
                .args(&env::args_os().skip(1).collect::<Vec<_>>())
                .status()
                .unwrap()
                .code()
                .unwrap_or(1),
        );
    }

    if let Ok(s) = env::var("TEST_ADDR") {
        let mut contents = Vec::new();
        TcpStream::connect(s)
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();
        return;
    }

    let c = Client::new_with_fifo(1).unwrap();
    let td = tempfile::tempdir().unwrap();

    let prog = env::var("MAKE").unwrap_or_else(|_| "make".to_string());

    let me = env::current_exe().unwrap();
    let me = me.to_str().unwrap();

    let mut cmd = Command::new(me);
    cmd.current_dir(td.path());
    cmd.env("MAKE", prog);
    cmd.env("_DO_THE_TEST", "1");

    File::create(td.path().join("Makefile"))
        .unwrap()
        .write_all(
            format!(
                "\
all: foo bar
foo:
\t{0}
bar:
\t{0}
",
                me
            )
            .as_bytes(),
        )
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    cmd.env("TEST_ADDR", addr.to_string());

    // We're leaking one extra token to `make` sort of violating the makefile
    // jobserver protocol. It has the desired effect though.
    let mut child = c
        .configure_make_and_run_with_fifo(&mut cmd, |cmd| cmd.spawn())
        .unwrap();

    // We should get both connections as the two programs should be run
    // concurrently.
    let a = listener.accept().unwrap();
    let b = listener.accept().unwrap();
    drop((a, b));

    assert!(child.wait().unwrap().success());
}
