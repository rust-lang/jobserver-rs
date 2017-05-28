//! An implementation of the GNU make jobserver.
//!
//! This crate is an implementation, in Rust, of the GNU `make` jobserver for
//! CLI tools that are interoperating with make or otherwise require some form
//! of parallelism limiting across process boundaries. This was originally
//! written for usage in Cargo to both (a) work when `cargo` is invoked from
//! `make` (using `make`'s jobserver) and (b) work when `cargo` invokes build
//! scripts, exporting a jobserver implementation for `make` processes to
//! transitively use.
//!
//! The jobserver implementation can be found in [detail online][docs] but
//! basically boils down to a cross-process semaphore. On Unix this is
//! implemented with the `pipe` syscall and read/write ends of a pipe and on
//! Windows this is implemented literally with IPC semaphores.
//!
//! The jobserver protocol in `make` also dictates when tokens are acquire to
//! run child work, and clients using this crate should take care to implement
//! such details to ensure correct interoperation with `make` itself.
//!
//! ## Examples
//!
//! Connect to a jobserver that was set up by `make` or a different process:
//!
//! ```no_run
//! use jobserver::Client;
//!
//! // See API documentation for why this is `unsafe`
//! let client = match unsafe { Client::from_env() } {
//!     Some(client) => client,
//!     None => panic!("client not configured"),
//! };
//! ```
//!
//! Acquire and release token from a jobserver:
//!
//! ```no_run
//! use jobserver::Client;
//!
//! let client = unsafe { Client::from_env().unwrap() };
//! let token = client.acquire().unwrap(); // blocks until it is available
//! drop(token); // releases the token when the work is done
//! ```
//!
//! Create a new jobserver and configure a child process to have access:
//!
//! ```
//! use std::process::Command;
//! use jobserver::Client;
//!
//! let client = Client::new(4).expect("failed to create jobserver");
//! let mut cmd = Command::new("make");
//! client.configure(&mut cmd);
//! ```
//!
//! ## Caveats
//!
//! This crate makes no attempt to release tokens back to a jobserver on
//! abnormal exit of a process. If a process which acquires a token is killed
//! with ctrl-c or some similar signal then tokens will not be released and the
//! jobserver may be in a corrupt state.
//!
//! Note that this is typically ok as ctrl-c means that an entire build process
//! is being torn down, but it's worth being aware of at least!
//!
//! ## Windows caveats
//!
//! There appear to be two implementations of `make` on Windows. On MSYS2 one
//! typically comes as `mingw32-make` and the other as `make` itself. I'm not
//! personally too familiar with what's going on here, but for jobserver-related
//! information the `mingw32-make` implementation uses Windows semaphores
//! whereas the `make` program does not. The `make` program appears to use file
//! descriptors and I'm not really sure how it works, so this crate is not
//! compatible with `make` on Windows. It is, however, compatible with
//! `mingw32-make`.
//!
//! [docs]: http://make.mad-scientist.net/papers/jobserver-implementation/

#![deny(missing_docs)]
#![doc(html_root_url = "https://docs.rs/jobserver/0.1")]

use std::env;
use std::io;
use std::process::Command;
use std::sync::Arc;

/// A client of a jobserver
///
/// This structure is the main type exposed by this library, and is where
/// interaction to a jobserver is configured through. Clients are either created
/// from scratch in which case the internal semphore is initialied on the spot,
/// or a client is created from the environment to connect to a jobserver
/// already created.
///
/// Some usage examples can be found in the crate documentation for using a
/// client.
///
/// Note that a `Client` implements the `Clone` trait, and all instances of a
/// `Client` refer to the same jobserver instance.
#[derive(Clone)]
pub struct Client {
    inner: Arc<imp::Client>,
}

/// An acquired token from a jobserver.
///
/// This token will be released back to the jobserver when it is dropped and
/// otherwise represents the ability to spawn off another thread of work.
pub struct Acquired {
    client: Arc<imp::Client>,
    data: imp::Acquired,
}

impl Client {
    /// Creates a new jobserver initialized with the given parallelism limit.
    ///
    /// A client to the jobserver created will be returned. This client will
    /// allow at most `limit` tokens to be acquired from it in parallel. More
    /// calls to `acquire` will cause the calling thread to block.
    ///
    /// Note that the created `Client` is not automatically inherited into
    /// spawned child processes from this program. Manual usage of the
    /// `configure` function is required for a child process to have access to a
    /// job server.
    ///
    /// # Examples
    ///
    /// ```
    /// use jobserver::Client;
    ///
    /// let client = Client::new(4).expect("failed to create jobserver");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if any I/O error happens when attempting to create the
    /// jobserver client.
    pub fn new(limit: usize) -> io::Result<Client> {
        Ok(Client {
            inner: Arc::new(imp::Client::new(limit)?),
        })
    }

    /// Attempts to connect to the jobserver specified in this process's
    /// environment.
    ///
    /// When the a `make` executable calls a child process it will configure the
    /// environment of the child to ensure that it has handles to the jobserver
    /// it's passing down. This function will attempt to look for these details
    /// and connect to the jobserver.
    ///
    /// Note that the created `Client` is not automatically inherited into
    /// spawned child processes from this program. Manual usage of the
    /// `configure` function is required for a child process to have access to a
    /// job server.
    ///
    /// # Return value
    ///
    /// If a jobserver was found in the environment and it looks correct then
    /// `Some` of the connected client will be returned. If no jobserver was
    /// found then `None` will be returned.
    ///
    /// Note that on Unix the `Client` returned **takes ownership of the file
    /// descriptors specified in the environment**. Jobservers on Unix are
    /// implemented with `pipe` file descriptors, and they're inherited from
    /// parent processes. This `Client` returned takes ownership of the file
    /// descriptors for this process and will close the file descriptors after
    /// this value is dropped.
    ///
    /// Additionally on Unix this function will configure the file descriptors
    /// with `CLOEXEC` so they're not automatically inherited by spawned
    /// children.
    ///
    /// # Unsafety
    ///
    /// This function is `unsafe` to call on Unix specifically as it
    /// transitively requires usage of the `from_raw_fd` function, which is
    /// itself unsafe in some circumstances.
    ///
    /// It's recommended to call this function very early in the lifetime of a
    /// program before any other file descriptors are opened. That way you can
    /// make sure to take ownership properly of the file descriptors passed
    /// down, if any.
    ///
    /// It's generally unsafe to call this function twice in a program if the
    /// previous invocation returned `Some`.
    ///
    /// Note, though, that on Windows it should be safe to call this function
    /// any number of times.
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

    /// Acquires a token from this jobserver client.
    ///
    /// This function will block the calling thread until a new token can be
    /// acquired from the jobserver.
    ///
    /// # Return value
    ///
    /// On successful acquisition of a token an instance of `Acquired` is
    /// returned. This structure, when dropped, will release the token back to
    /// the jobserver. It's recommended to avoid leaking this value.
    ///
    /// # Errors
    ///
    /// If an I/O error happens while acquiring a token then this function will
    /// return immediately with the error. If an error is returned then a token
    /// was not acquired.
    pub fn acquire(&self) -> io::Result<Acquired> {
        let data = try!(self.inner.acquire());
        Ok(Acquired {
            client: self.inner.clone(),
            data: data,
        })
    }

    /// Configures a child process to have access to this client's jobserver as
    /// well.
    ///
    /// This function is required to be called to ensure that a jobserver is
    /// properly inherited to a child process. If this function is *not* called
    /// then this `Client` will not be accessible in the child process. In other
    /// words, if not called, then `Client::from_env` will return `None` in the
    /// child process (or the equivalent of `Child::from_env` that `make` uses).
    ///
    /// ## Platform-specific behavior
    ///
    /// On Unix and Windows this will clobber the `MAKEFLAGS` and `MFLAGS`
    /// environment variables for the child process, and on Unix this will also
    /// allow the two file descriptors for this client to be inherited to the
    /// child.
    pub fn configure(&self, cmd: &mut Command) {
        let arg = self.inner.string_arg();
        // Older implementations of make use `--jobserver-fds` and newer
        // implementations use `--jobserver-auth`, pass both to try to catch
        // both implementations.
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
            // I don't think the character written here matters, but I could be
            // wrong!
            for _ in 0..limit {
                (&client.write).write(&[b'|'])?;
            }
            Ok(client)
        }

        unsafe fn mk() -> io::Result<Client> {
            let mut pipes = [0; 2];

            // Attempt atomically-create-with-cloexec if we can
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
            let mut parts = s.splitn(2, ',');
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

            // Ok so we've got two integers that look like file descriptors, but
            // for extra sanity checking let's see if they actually look like
            // instances of a pipe before we return the client.
            //
            // If we're called from `make` *without* the leading + on our rule
            // then we'll have `MAKEFLAGS` env vars but won't actually have
            // access to the file descriptors.
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
            // Here we basically just want to say that in the child process
            // we'll configure the read/write file descriptors to *not* be
            // cloexec, so they're inherited across the exec and specified as
            // integers through `string_arg` above.
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

    // HANDLE is a raw ptr, but we're send/sync
    unsafe impl Sync for Client {}
    unsafe impl Send for Client {}

    pub struct Acquired;

    const SEMAPHORE_MODIFY_STATE: winapi::DWORD = 0x2;

    impl Client {
        pub fn new(limit: usize) -> io::Result<Client> {
            // Try a bunch of random semaphore names until we get a unique one,
            // but don't try for too long.
            for _ in 0..100 {
                let mut name = format!("__rust_jobserver_semaphore_{}\0",
                                       rand::random::<u32>());
                unsafe {
                    let r = kernel32::CreateSemaphoreA(ptr::null_mut(),
                                                       limit as winapi::LONG,
                                                       limit as winapi::LONG,
                                                       name.as_ptr() as *const _);
                    if r.is_null() {
                        return Err(io::Error::last_os_error())
                    }

                    let err = io::Error::last_os_error();
                    if err.raw_os_error() == Some(winapi::ERROR_ALREADY_EXISTS as i32) {
                        continue
                    }
                    name.pop(); // chop off the trailing nul
                    return Ok(Client {
                        sem: r,
                        name: name,
                    })
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
            // nothing to do here, we gave the name of our semaphore to the
            // child above
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
