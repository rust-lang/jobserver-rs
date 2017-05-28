use std::env;
use std::io;
use std::process::Command;
use std::sync::Arc;

#[derive(Clone)]
pub struct Client {
    inner: Arc<imp::Client>,
}

pub struct Acquired {
    client: Arc<imp::Client>,
    data: imp::Acquired,
}

impl Client {
    pub fn new(limit: usize) -> io::Result<Client> {
        Ok(Client {
            inner: Arc::new(imp::Client::new(limit)?),
        })
    }

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

    pub fn configure(&self, cmd: &mut Command) {
        let arg = self.inner.string_arg();
        let value = format!("--jobserver-fds={0} --jobserver-auth={0}", arg);
        cmd.env("MAKEFLAGS", &value);
        cmd.env("MFLAGS", &value);
        self.inner.configure(cmd);
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
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, ATOMIC_USIZE_INIT, Ordering};

    use self::libc::c_int;

    pub struct Client {
        read: File,
        write: File,
    }

    pub struct Acquired {
        byte: u8,
    }

    impl Client {
        pub fn new(limit: usize) -> io::Result<Client> {
            let client = unsafe { Client::mk()? };
            for _ in 0..limit {
                (&client.write).write(&[b'|'])?;
            }
            Ok(client)
        }

        unsafe fn mk() -> io::Result<Client> {
            let mut pipes = [0; 2];
            if cfg!(target_os = "linux") {
                if let Some(pipe2) = pipe2() {
                    cvt(pipe2(pipes.as_mut_ptr(), libc::O_CLOEXEC))?;
                    return Ok(Client::from_fds(pipes[0], pipes[1]))
                }
            }

            cvt(libc::pipe(pipes.as_mut_ptr()))?;
            drop(set_cloexec(pipes[0], true));
            drop(set_cloexec(pipes[1], true));
            Ok(Client::from_fds(pipes[0], pipes[1]))
        }

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
                drop(set_cloexec(read, true));
                drop(set_cloexec(write, true));
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

        pub fn string_arg(&self) -> String {
            format!("{},{} -j", self.read.as_raw_fd(), self.write.as_raw_fd())
        }

        pub fn configure(&self, cmd: &mut Command) {
            let read = self.read.as_raw_fd();
            let write = self.write.as_raw_fd();
            cmd.before_exec(move || {
                set_cloexec(read, false)?;
                set_cloexec(write, false)?;
                Ok(())
            });
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

    fn set_cloexec(fd: c_int, set: bool) -> io::Result<()> {
        unsafe {
            let previous = cvt(libc::fcntl(fd, libc::F_GETFD))?;
            let new = if set {
                previous | libc::FD_CLOEXEC
            } else {
                previous & !libc::FD_CLOEXEC
            };
            if new != previous {
                cvt(libc::fcntl(fd, libc::F_SETFD, new))?;
            }
            Ok(())
        }
    }

    fn cvt(t: c_int) -> io::Result<c_int> {
        if t == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(t)
        }
    }

    unsafe fn pipe2() -> Option<&'static fn(*mut c_int, c_int) -> c_int> {
        static PIPE2: AtomicUsize = ATOMIC_USIZE_INIT;

        if PIPE2.load(Ordering::SeqCst) == 0 {
            let name = "pipe2\0";
            let n = match libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr() as *const _) as usize {
                0 => 1,
                n => n,
            };
            PIPE2.store(n, Ordering::SeqCst);
        }
        if PIPE2.load(Ordering::SeqCst) == 1 {
            None
        } else {
            mem::transmute(&PIPE2)
        }
    }
}

#[cfg(windows)]
mod imp {
    extern crate kernel32;
    extern crate rand;
    extern crate winapi;

    use std::ffi::CString;
    use std::io;
    use std::process::Command;
    use std::ptr;

    pub struct Client {
        sem: winapi::HANDLE,
        name: String,
    }

    unsafe impl Sync for Client {}
    unsafe impl Send for Client {}

    pub struct Acquired;

    const SEMAPHORE_MODIFY_STATE: winapi::DWORD = 0x2;

    impl Client {
        pub fn new(limit: usize) -> io::Result<Client> {
            for _ in 0..100 {
                let mut name = format!("__rust_jobserver_semaphore_{}\0",
                                       rand::random::<u32>());
                unsafe {
                    let r = kernel32::CreateSemaphoreA(ptr::null_mut(),
                                                       limit as winapi::LONG,
                                                       limit as winapi::LONG,
                                                       name.as_ptr() as *const _);
                    if !r.is_null() {
                        name.pop();
                        return Ok(Client {
                            sem: r,
                            name: name,
                        })
                    }

                    let err = io::Error::last_os_error();
                    if err.raw_os_error() == Some(winapi::ERROR_ALREADY_EXISTS as i32) {
                        continue
                    }
                    return Err(err)
                }
            }

            Err(io::Error::new(io::ErrorKind::Other,
                               "failed to find a unique name for a semaphore"))
        }

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
                Some(Client {
                    sem: sem,
                    name: s.to_string(),
                })
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

        pub fn string_arg(&self) -> String {
            self.name.clone()
        }

        pub fn configure(&self, _cmd: &mut Command) {
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
