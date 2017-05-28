use std::env;
use std::sync::Arc;
use std::io;

#[derive(Clone)]
pub struct Client {
    inner: Arc<imp::Client>,
}

pub struct Acquired {
    client: Arc<imp::Client>,
    data: imp::Acquired,
}

impl Client {
    pub unsafe fn from_env() -> Option<Client> {
        let var = match env::var("MAKEFLAGS").or(env::var("MFLAGS")) {
            Ok(s) => s,
            Err(_) => return None,
        };
        let mut arg = "--jobserver-fds=";
        let pos = match var.find(arg) {
            Some(i) => i,
            None => {
                arg = "--jobserver-auth=";
                match var.find(arg) {
                    Some(i) => i,
                    None => return None,
                }
            }
        };

        let s = var[pos + arg.len()..].split(' ').next().unwrap();
        imp::Client::open(s).map(|c| {
            Client { inner: Arc::new(c) }
        })
    }

    pub fn acquire(&self) -> io::Result<Acquired> {
        let data = try!(self.inner.acquire());
        Ok(Acquired {
            client: self.inner.clone(),
            data: data,
        })
    }
}

impl Drop for Acquired {
    fn drop(&mut self) {
        drop(self.client.release(&self.data));
    }
}

#[cfg(unix)]
mod imp {
    extern crate libc;

    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::mem;
    use std::os::unix::prelude::*;

    use self::libc::c_int;

    pub struct Client {
        read: File,
        write: File,
    }

    pub struct Acquired {
        byte: u8,
    }

    impl Client {
        pub unsafe fn open(s: &str) -> Option<Client> {
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

        unsafe fn from_fds(read: c_int, write: c_int) -> Client {
            Client {
                read: File::from_raw_fd(read),
                write: File::from_raw_fd(write),
            }
        }

        pub fn acquire(&self) -> io::Result<Acquired> {
            let mut buf = [0];
            (&self.read).read_exact(&mut buf)?;
            Ok(Acquired { byte: buf[0] })
        }

        pub fn release(&self, data: &Acquired) -> io::Result<()> {
            (&self.write).write(&[data.byte])?;
            Ok(())
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
}

#[cfg(windows)]
mod imp {
    extern crate winapi;
    extern crate kernel32;

    use std::ffi::CString;
    use std::io;
    use std::ptr;

    pub struct Client {
        sem: winapi::HANDLE,
    }

    unsafe impl Sync for Client {}
    unsafe impl Send for Client {}

    pub struct Acquired;

    const SEMAPHORE_MODIFY_STATE: winapi::DWORD = 0x2;

    impl Client {
        pub unsafe fn open(s: &str) -> Option<Client> {
            let name = match CString::new(s) {
                Ok(s) => s,
                Err(_) => return None,
            };

            let sem = kernel32::OpenSemaphoreA(winapi::SYNCHRONIZE |
                                                SEMAPHORE_MODIFY_STATE,
                                               winapi::FALSE,
                                               name.as_ptr());
            if sem.is_null() {
                None
            } else {
                Some(Client { sem: sem })
            }
        }

        pub fn acquire(&self) -> io::Result<Acquired> {
            unsafe {
                let r = kernel32::WaitForSingleObject(self.sem,
                                                      winapi::INFINITE);
                if r == winapi::WAIT_OBJECT_0 {
                    Ok(Acquired)
                } else {
                    Err(io::Error::last_os_error())
                }
            }
        }

        pub fn release(&self, _data: &Acquired) -> io::Result<()> {
            unsafe {
                let r = kernel32::ReleaseSemaphore(self.sem, 1, ptr::null_mut());
                if r != 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            }
        }
    }

    impl Drop for Client {
        fn drop(&mut self) {
            unsafe {
                kernel32::CloseHandle(self.sem);
            }
        }
    }
}
