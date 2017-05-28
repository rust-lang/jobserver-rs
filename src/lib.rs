extern crate libc;

use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem;
use std::os::unix::prelude::*;
use std::sync::Arc;

use libc::c_int;

#[derive(Clone)]
pub struct Client {
    read: Arc<File>,
    write: Arc<File>,
}

pub struct Acquired {
    write: Arc<File>,
    byte: u8,
}

impl Client {
    pub unsafe fn from_env() -> Option<Client> {
        let var = match env::var("MAKEFLAGS").or(env::var("MFLAGS")) {
            Ok(s) => s,
            Err(_) => return None,
        };
        let arg = "--jobserver-fds=";
        let pos = match var.find(arg) {
            Some(i) => i,
            None => return None,
        };
        let s = var[pos + arg.len()..].split(' ').next().unwrap();
        let mut parts = s.split(',');
        let read = parts.next().unwrap();
        let write = match parts.next() {
            Some(s) => s,
            None => return None,
        };

        let read = match read.parse() {
            Ok(n) => n,
            Err(_) => return None,
        };
        let write = match write.parse() {
            Ok(n) => n,
            Err(_) => return None,
        };
        if is_pipe(read) && is_pipe(write) {
            Some(Client::from_fds(read, write))
        } else {
            None
        }
    }

    pub unsafe fn from_fds(read: c_int, write: c_int) -> Client {
        Client {
            read: Arc::new(File::from_raw_fd(read)),
            write: Arc::new(File::from_raw_fd(write)),
        }
    }

    pub fn acquire(&self) -> io::Result<Acquired> {
        let mut buf = [0];
        (&*self.read).read_exact(&mut buf)?;
        Ok(Acquired {
            byte: buf[0],
            write: self.write.clone(),
        })
    }
}

fn is_pipe(fd: c_int) -> bool {
    unsafe {
        let mut stat = mem::zeroed();
        if libc::fstat(fd, &mut stat) == 0 {
            stat.st_mode & libc::S_IFIFO == libc::S_IFIFO
        } else {
            false
        }
    }
}

impl Drop for Acquired {
    fn drop(&mut self) {
        drop((&*self.write).write(&[self.byte]));
    }
}
