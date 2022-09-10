use libc::c_int;

use std::{
    borrow::Cow,
    fs::File,
    io::{self, Read, Write},
    mem::MaybeUninit,
    os::unix::prelude::*,
    sync::Arc,
    thread::{Builder, JoinHandle},
};

#[derive(Debug)]
pub struct Client {
    /// This fd is set to be blocking
    read: File,
    /// This fd is set to be blocking
    write: File,
}

#[derive(Debug)]
pub struct Acquired {
    byte: u8,
}

impl Client {
    pub fn new(mut limit: usize) -> io::Result<Client> {
        let client = Client::mk()?;

        // I don't think the character written here matters, but I could be
        // wrong!
        const BUFFER: [u8; 128] = [b'|'; 128];

        set_nonblocking(client.write.as_raw_fd(), true)?;

        while limit > 0 {
            let n = limit.min(BUFFER.len());

            (&client.write).write_all(&BUFFER[..n])?;
            limit -= n;
        }

        set_nonblocking(client.write.as_raw_fd(), false)?;

        Ok(client)
    }

    fn mk() -> io::Result<Client> {
        let pipes = create_pipe()?;

        Ok(unsafe { Client::from_fds(pipes[0], pipes[1]) })
    }

    pub unsafe fn open(s: &str) -> Option<Client> {
        let (read, write) = s.split_once(',')?;

        let read = read.parse().ok()?;
        let write = write.parse().ok()?;

        // Ok so we've got two integers that look like file descriptors, but
        // for extra sanity checking let's see if they actually look like
        // instances of a pipe before we return the client.
        //
        // If we're called from `make` *without* the leading + on our rule
        // then we'll have `MAKEFLAGS` env vars but won't actually have
        // access to the file descriptors.
        if is_pipe(read, true) && is_pipe(write, false) {
            let read = dup(read).ok()?;
            let write = dup(write).ok()?;

            drop(set_cloexec(read, true));
            drop(set_nonblocking(read, false));

            drop(set_cloexec(write, true));
            drop(set_nonblocking(write, false));

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
        // Also note that we explicitly don't handle EINTR here. That's used
        // to shut us down, so we otherwise punt all errors upwards.
        let mut buf = [0];
        match (&self.read).read(&mut buf) {
            Ok(1) => Ok(Some(Acquired { byte: buf[0] })),
            Ok(_) => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(None),
            Err(e) => Err(e),
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
            _ => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
        }
    }

    pub fn string_arg(&self) -> Cow<'_, str> {
        Cow::Owned(format!(
            "{},{}",
            self.read.as_raw_fd(),
            self.write.as_raw_fd()
        ))
    }

    pub fn pre_run(&self) -> io::Result<()> {
        set_cloexec(self.read.as_raw_fd(), false)?;
        set_cloexec(self.write.as_raw_fd(), false)?;

        Ok(())
    }

    pub fn post_run(&self) -> io::Result<()> {
        set_cloexec(self.read.as_raw_fd(), true)?;
        set_cloexec(self.write.as_raw_fd(), true)?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct Helper {
    thread: JoinHandle<()>,
    state: Arc<super::HelperState>,
    shutdown_tx: File,
}

pub(crate) fn spawn_helper(
    client: crate::Client,
    state: Arc<super::HelperState>,
    mut f: Box<dyn FnMut(io::Result<crate::Acquired>) + Send>,
) -> io::Result<Helper> {
    let pipes = create_pipe()?;

    let mut shutdown_rx = unsafe { File::from_raw_fd(pipes[0]) };
    let shutdown_tx = unsafe { File::from_raw_fd(pipes[1]) };

    let read = dup(client.inner.read.as_raw_fd())?;
    let mut read = unsafe { File::from_raw_fd(read) };

    set_nonblocking(read.as_raw_fd(), true)?;
    set_nonblocking(shutdown_rx.as_raw_fd(), true)?;

    let state2 = state.clone();
    let thread = Builder::new().spawn(move || {
        state2.for_each_request(|helper| {
            if let Some(res) = helper_thread_loop(helper, &mut read, &mut shutdown_rx).transpose() {
                f(res.map(|data| crate::Acquired {
                    client: client.inner.clone(),
                    data,
                    disabled: false,
                }))
            }
        });
    })?;

    Ok(Helper {
        thread,
        state,
        shutdown_tx,
    })
}

fn helper_thread_loop(
    helper: &crate::HelperState,
    read: &mut File,
    shutdown_rx: &mut File,
) -> io::Result<Option<Acquired>> {
    let fds = [read.as_raw_fd(), shutdown_rx.as_raw_fd()];

    loop {
        if helper.producer_done() {
            break Ok(None);
        }

        let (can_acquire, shutdown_requested) = poll_for_readiness(fds)?;
        if shutdown_requested {
            break Ok(None);
        } else if can_acquire {
            let mut buf = [0];
            match read.read(&mut buf) {
                Ok(1) => break Ok(Some(Acquired { byte: buf[0] })),
                Ok(_) => break Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Err(e)
                    if e.kind() == io::ErrorKind::Interrupted
                        || e.kind() == io::ErrorKind::WouldBlock =>
                {
                    continue;
                }
                Err(e) => break Err(e),
            }
        }
    }
}

impl Helper {
    pub fn join(mut self) {
        let state = self.state.lock();
        debug_assert!(state.producer_done);

        // We need to join our helper thread, and it could be blocked in one
        // of two locations. First is the wait for a request, but the
        // initial drop of `HelperState` will take care of that. Otherwise
        // it may be blocked in `client.acquire()`.
        //
        // Since we use `poll` in the helper thread, we can simply write to
        // shutdown_tx to end the thread.
        //
        // If somehow this fails, then it means that the other thread
        // is alredy terminated.
        let _ = self.shutdown_tx.write(&[1]);

        if state.consumer_done {
            drop(self.thread.join());
        }
    }
}

fn create_pipe() -> io::Result<[RawFd; 2]> {
    let mut pipes = [0; 2];

    // Attempt atomically-create-with-cloexec if we can on Linux,
    // detected by using the `syscall` function in `libc` to try to work
    // with as many kernels/glibc implementations as possible.
    #[cfg(target_os = "linux")]
    {
        use std::sync::atomic::{AtomicBool, Ordering};

        static PIPE2_AVAILABLE: AtomicBool = AtomicBool::new(true);
        if PIPE2_AVAILABLE.load(Ordering::Relaxed) {
            match cvt(unsafe { libc::pipe2(pipes.as_mut_ptr(), libc::O_CLOEXEC) }) {
                Ok(_) => return Ok(pipes),
                Err(err) if err.raw_os_error() != Some(libc::ENOSYS) => return Err(err),

                // err.raw_os_error() == Some(libc::ENOSYS)
                _ => PIPE2_AVAILABLE.store(false, Ordering::Relaxed),
            }
        }
    }

    cvt(unsafe { libc::pipe(pipes.as_mut_ptr()) })?;
    drop(set_cloexec(pipes[0], true));
    drop(set_cloexec(pipes[1], true));

    Ok(pipes)
}

fn set_cloexec(fd: c_int, set: bool) -> io::Result<()> {
    let previous = cvt(unsafe { libc::fcntl(fd, libc::F_GETFD) })?;
    let new = if set {
        previous | libc::FD_CLOEXEC
    } else {
        previous & !libc::FD_CLOEXEC
    };
    if new != previous {
        cvt(unsafe { libc::fcntl(fd, libc::F_SETFD, new) })?;
    }
    Ok(())
}

fn set_nonblocking(fd: c_int, set: bool) -> io::Result<()> {
    let status_flag = if set { libc::O_NONBLOCK } else { 0 };

    unsafe {
        cvt(libc::fcntl(fd, libc::F_SETFL, status_flag))?;
    }

    Ok(())
}

fn dup(fd: c_int) -> io::Result<c_int> {
    cvt(unsafe { libc::dup(fd) })
}

fn cvt(t: c_int) -> io::Result<c_int> {
    if t == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(t)
    }
}

fn is_pipe(fd: RawFd, readable: bool) -> bool {
    let mut stat = MaybeUninit::<libc::stat>::uninit();

    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } == -1 {
        return false;
    }

    // Safety:
    //
    // libc::fstat succeeds, stat is initialized
    let stat = unsafe { stat.assume_init() };
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFIFO {
        // fd is not a pipe
        return false;
    }

    let ret = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if ret == -1 {
        return false;
    }

    let status_flags = ret;
    let access_mode = if readable {
        libc::O_RDONLY
    } else {
        libc::O_WRONLY
    };

    (status_flags & libc::O_ACCMODE) == access_mode
}

/// NOTE that this is a blocking syscall, it will block
/// until one of the fd is ready.
fn poll_for_readiness(fds: [RawFd; 2]) -> io::Result<(bool, bool)> {
    let mut fds = [
        libc::pollfd {
            fd: fds[0],
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: fds[1],
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    loop {
        let ret = cvt(unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) })?;
        if ret != 0 {
            break;
        }
    }

    Ok((is_ready(fds[0].revents)?, is_ready(fds[1].revents)?))
}

fn is_ready(revents: libc::c_short) -> io::Result<bool> {
    use libc::{POLLERR, POLLHUP, POLLIN, POLLNVAL};

    match revents {
        POLLERR | POLLHUP | POLLIN => Ok(true),
        // This should be very rare
        POLLNVAL => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fd of is invalid",
        )),
        _ => Ok(false),
    }
}
