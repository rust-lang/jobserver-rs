use libc::c_int;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem;
use std::os::unix::prelude::*;
use std::process::Command;
use std::ptr;
use std::sync::{Arc, Once};
use std::thread::{self, Builder, JoinHandle};
use std::time::Duration;

#[derive(Debug)]
pub struct Client {
    read: File,
    write: File,
}

#[derive(Debug)]
pub struct Acquired {
    byte: u8,
}

impl Client {
    pub fn new(limit: usize) -> io::Result<Client> {
        let client = unsafe { Client::mk()? };
        client.configure_capacity(limit)?;
        // I don't think the character written here matters, but I could be
        // wrong!
        for _ in 0..limit {
            (&client.write).write_all(&[b'|'])?;
        }
        Ok(client)
    }

    unsafe fn mk() -> io::Result<Client> {
        let mut pipes = [0; 2];

        // Attempt atomically-create-with-cloexec if we can on Linux,
        // detected by using the `syscall` function in `libc` to try to work
        // with as many kernels/glibc implementations as possible.
        #[cfg(target_os = "linux")]
        {
            use std::sync::atomic::{AtomicBool, Ordering};

            static PIPE2_AVAILABLE: AtomicBool = AtomicBool::new(true);
            if PIPE2_AVAILABLE.load(Ordering::SeqCst) {
                match libc::syscall(libc::SYS_pipe2, pipes.as_mut_ptr(), libc::O_CLOEXEC) {
                    -1 => {
                        let err = io::Error::last_os_error();
                        if err.raw_os_error() == Some(libc::ENOSYS) {
                            PIPE2_AVAILABLE.store(false, Ordering::SeqCst);
                        } else {
                            return Err(err);
                        }
                    }
                    _ => return Ok(Client::from_fds(pipes[0], pipes[1])),
                }
            }
        }

        cvt(libc::pipe(pipes.as_mut_ptr()))?;
        drop(set_cloexec(pipes[0], true));
        drop(set_cloexec(pipes[1], true));
        Ok(Client::from_fds(pipes[0], pipes[1]))
    }

    fn configure_capacity(&self, required_capacity: usize) -> io::Result<()> {
        // On Linux we may need to increase the capacity of the pipe for the
        // jobserver to work correctly. Linux seems to exhibit behavior where it
        // implements a ring-buffer internally but apparently the ring-ness of
        // the ring-buffer is connected to *pages* of the ring buffer rather
        // than actual bytes of the ring buffer. This means that if the pipe has
        // only one page of capacity we can hit a possible deadlock situation
        // where a bunch of threads are writing to the pipe but they're all
        // blocked, despite the current used capacity of the pipe being less
        // than a page.
        //
        // This was first discovered in rust-lang/cargo#9739 where a system with
        // a large amount of concurrency would hang in `cargo build` when the
        // jobserver pipe only had one page of capacity. This was reduced to a
        // reproduction program [1] which indeed showed that the system would
        // deadlock if the capacity of the pipe was just one page.
        //
        // To fix this issue, on Linux only, we may increase the capacity of the
        // pipe. The main thing here is that if the capacity of the pipe is a
        // single page we try to increase it to two pages, otherwise we fail
        // because a deadlock might happen. While we're at it this goes ahead
        // and factors in the `required_capacity` requested by the client to
        // this calculation as well. If for some reason you want 10_000 units of
        // concurrency in the pipe that means we'll need more than 2 pages
        // (typically 8192 bytes), so we round that up to 3 pages as well.
        //
        // Someone with more understanding of linux pipes and how they buffer
        // internally should probably review this at some point. The exact cause
        // of the deadlock seems a little uncertain and it's not clear why the
        // example program [1] deadlocks and why simply adding another page
        // fixes things. Is this a kernel bug? Do we need to always guarantee at
        // least one free page? I'm not sure! Hopefully for now this is enough
        // to fix the problem until machines start having more than 4k cores,
        // which seems like it might be awhile.
        //
        // [1]: https://github.com/rust-lang/cargo/issues/9739#issuecomment-889183009
        #[cfg(target_os = "linux")]
        unsafe {
            let page_size = libc::sysconf(libc::_SC_PAGESIZE);
            let actual_capacity = cvt(libc::fcntl(self.write.as_raw_fd(), libc::F_GETPIPE_SZ))?;

            if let Some(c) = calculate_capacity(
                required_capacity,
                actual_capacity as usize,
                page_size as usize,
            ) {
                cvt(libc::fcntl(self.write.as_raw_fd(), libc::F_SETPIPE_SZ, c)).map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!(
                            "failed to increase jobserver pipe capacity from {} to {}; \
                             jobserver otherwise might deadlock",
                            actual_capacity, c,
                        ),
                    )

                    // ...
                })?;
            }
        }

        Ok(())
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
        if is_valid_fd(read) && is_valid_fd(write) {
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
        // Ignore interrupts and keep trying if that happens
        loop {
            if let Some(token) = self.acquire_allow_interrupts()? {
                return Ok(token);
            }
        }
    }

    /// Block waiting for a token, returning `None` if we're interrupted with
    /// EINTR.
    fn acquire_allow_interrupts(&self) -> io::Result<Option<Acquired>> {
        // We don't actually know if the file descriptor here is set in
        // blocking or nonblocking mode. AFAIK all released versions of
        // `make` use blocking fds for the jobserver, but the unreleased
        // version of `make` doesn't. In the unreleased version jobserver
        // fds are set to nonblocking and combined with `pselect`
        // internally.
        //
        // Here we try to be compatible with both strategies. We optimistically
        // try to read from the file descriptor which then may block, return
        // a token or indicate that polling is needed.
        // Blocking reads (if possible) allows the kernel to be more selective
        // about which readers to wake up when a token is written to the pipe.
        //
        // We use `poll` here to block this thread waiting for read
        // readiness, and then afterwards we perform the `read` itself. If
        // the `read` returns that it would block then we start over and try
        // again.
        //
        // Also note that we explicitly don't handle EINTR here. That's used
        // to shut us down, so we otherwise punt all errors upwards.
        unsafe {
            let mut fd: libc::pollfd = mem::zeroed();
            fd.fd = self.read.as_raw_fd();
            fd.events = libc::POLLIN;
            loop {
                let mut buf = [0];
                match (&self.read).read(&mut buf) {
                    Ok(1) => return Ok(Some(Acquired { byte: buf[0] })),
                    Ok(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "early EOF on jobserver pipe",
                        ))
                    }
                    Err(e) => match e.kind() {
                        io::ErrorKind::WouldBlock => { /* fall through to polling */ }
                        io::ErrorKind::Interrupted => return Ok(None),
                        _ => return Err(e),
                    },
                }

                loop {
                    fd.revents = 0;
                    if libc::poll(&mut fd, 1, -1) == -1 {
                        let e = io::Error::last_os_error();
                        return match e.kind() {
                            io::ErrorKind::Interrupted => Ok(None),
                            _ => Err(e),
                        };
                    }
                    if fd.revents != 0 {
                        break;
                    }
                }
            }
        }
    }

    pub fn release(&self, data: Option<&Acquired>) -> io::Result<()> {
        // Note that the fd may be nonblocking but we're going to go ahead
        // and assume that the writes here are always nonblocking (we can
        // always quickly release a token). If that turns out to not be the
        // case we'll get an error anyway!
        let byte = data.map(|d| d.byte).unwrap_or(b'+');
        match (&self.write).write(&[byte])? {
            1 => Ok(()),
            _ => Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to write token back to jobserver",
            )),
        }
    }

    pub fn string_arg(&self) -> String {
        format!("{},{}", self.read.as_raw_fd(), self.write.as_raw_fd())
    }

    pub fn configure(&self, cmd: &mut Command) {
        // Here we basically just want to say that in the child process
        // we'll configure the read/write file descriptors to *not* be
        // cloexec, so they're inherited across the exec and specified as
        // integers through `string_arg` above.
        let read = self.read.as_raw_fd();
        let write = self.write.as_raw_fd();
        unsafe {
            cmd.pre_exec(move || {
                set_cloexec(read, false)?;
                set_cloexec(write, false)?;
                Ok(())
            });
        }
    }
}

#[derive(Debug)]
pub struct Helper {
    thread: JoinHandle<()>,
    state: Arc<super::HelperState>,
}

pub(crate) fn spawn_helper(
    client: crate::Client,
    state: Arc<super::HelperState>,
    mut f: Box<dyn FnMut(io::Result<crate::Acquired>) + Send>,
) -> io::Result<Helper> {
    static USR1_INIT: Once = Once::new();
    let mut err = None;
    USR1_INIT.call_once(|| unsafe {
        let mut new: libc::sigaction = mem::zeroed();
        new.sa_sigaction = sigusr1_handler as usize;
        new.sa_flags = libc::SA_SIGINFO as _;
        if libc::sigaction(libc::SIGUSR1, &new, ptr::null_mut()) != 0 {
            err = Some(io::Error::last_os_error());
        }
    });

    if let Some(e) = err.take() {
        return Err(e);
    }

    let state2 = state.clone();
    let thread = Builder::new().spawn(move || {
        state2.for_each_request(|helper| loop {
            match client.inner.acquire_allow_interrupts() {
                Ok(Some(data)) => {
                    break f(Ok(crate::Acquired {
                        client: client.inner.clone(),
                        data,
                        disabled: false,
                    }))
                }
                Err(e) => break f(Err(e)),
                Ok(None) if helper.producer_done() => break,
                Ok(None) => {}
            }
        });
    })?;

    Ok(Helper { thread, state })
}

impl Helper {
    pub fn join(self) {
        let dur = Duration::from_millis(10);
        let mut state = self.state.lock();
        debug_assert!(state.producer_done);

        // We need to join our helper thread, and it could be blocked in one
        // of two locations. First is the wait for a request, but the
        // initial drop of `HelperState` will take care of that. Otherwise
        // it may be blocked in `client.acquire()`. We actually have no way
        // of interrupting that, so resort to `pthread_kill` as a fallback.
        // This signal should interrupt any blocking `read` call with
        // `io::ErrorKind::Interrupt` and cause the thread to cleanly exit.
        //
        // Note that we don't do this forever though since there's a chance
        // of bugs, so only do this opportunistically to make a best effort
        // at clearing ourselves up.
        for _ in 0..100 {
            if state.consumer_done {
                break;
            }
            unsafe {
                // Ignore the return value here of `pthread_kill`,
                // apparently on OSX if you kill a dead thread it will
                // return an error, but on other platforms it may not. In
                // that sense we don't actually know if this will succeed or
                // not!
                libc::pthread_kill(self.thread.as_pthread_t() as _, libc::SIGUSR1);
            }
            state = self
                .state
                .cvar
                .wait_timeout(state, dur)
                .unwrap_or_else(|e| e.into_inner())
                .0;
            thread::yield_now(); // we really want the other thread to run
        }

        // If we managed to actually see the consumer get done, then we can
        // definitely wait for the thread. Otherwise it's... off in the ether
        // I guess?
        if state.consumer_done {
            drop(self.thread.join());
        }
    }
}

fn is_valid_fd(fd: c_int) -> bool {
    unsafe { libc::fcntl(fd, libc::F_GETFD) != -1 }
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

extern "C" fn sigusr1_handler(
    _signum: c_int,
    _info: *mut libc::siginfo_t,
    _ptr: *mut libc::c_void,
) {
    // nothing to do
}

#[allow(dead_code)]
fn calculate_capacity(
    required_capacity: usize,
    actual_capacity: usize,
    page_size: usize,
) -> Option<usize> {
    if actual_capacity < required_capacity {
        let mut rounded_capacity = round_up_to(required_capacity, page_size);
        if rounded_capacity < page_size * 2 {
            rounded_capacity += page_size;
        }
        return Some(rounded_capacity);
    }

    if actual_capacity <= page_size {
        return Some(page_size * 2);
    }

    return None;

    fn round_up_to(a: usize, b: usize) -> usize {
        assert!(b.is_power_of_two());
        (a + (b - 1)) & (!(b - 1))
    }
}

#[cfg(test)]
mod tests {
    use super::calculate_capacity;

    #[test]
    fn test_calculate_capacity() {
        assert_eq!(calculate_capacity(1, 65536, 4096), None);
        assert_eq!(calculate_capacity(500, 65536, 4096), None);
        assert_eq!(calculate_capacity(5000, 4096, 4096), Some(8192));
        assert_eq!(calculate_capacity(1, 4096, 4096), Some(8192));
        assert_eq!(calculate_capacity(4096, 4096, 4096), Some(8192));
        assert_eq!(calculate_capacity(8192, 4096, 4096), Some(8192));
    }
}
