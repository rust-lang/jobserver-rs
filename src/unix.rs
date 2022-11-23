use libc::c_int;

use std::{
    borrow::Cow,
    convert::TryInto,
    fs::File,
    io::{self, Read, Write},
    mem::MaybeUninit,
    os::unix::prelude::*,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    thread::{Builder, JoinHandle},
};

use crate::Command;

/// Lowest file descriptor used in `Selector::try_clone`.
///
/// # Notes
///
/// Usually fds 0, 1 and 2 are standard in, out and error. Some application
/// blindly assume this to be true, which means using any one of those a select
/// could result in some interesting and unexpected errors. Avoid that by using
/// an fd that doesn't have a pre-determined usage.
const LOWEST_FD: libc::c_int = 3;

#[derive(Debug)]
pub struct Client {
    /// This fd is set to be nonblocking
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
        // Create nonblocking and cloexec pipes
        let pipes = create_pipe(true)?;

        let client = unsafe { Client::from_fds(pipes[0], pipes[1]) };

        // I don't think the character written here matters, but I could be
        // wrong!
        const BUFFER: [u8; 128] = [b'|'; 128];

        while limit > 0 {
            let n = limit.min(BUFFER.len());

            // Use nonblocking write here so that if the pipe
            // would block, then return err instead of blocking
            // the entire process forever.
            (&client.write).write_all(&BUFFER[..n])?;
            limit -= n;
        }

        // Set fd to be blocking
        set_nonblocking(client.write.as_raw_fd(), false)?;

        Ok(client)
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
            let read = dup_with_cloexec(read).ok()?;
            let write = dup_with_cloexec(write).ok()?;

            // Set read to nonblocking
            set_nonblocking(read, true).ok()?;
            // Set write to blocking
            set_nonblocking(write, false).ok()?;

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
        loop {
            poll_for_readiness1(self.read.as_raw_fd())?;

            // Ignore EINTR or EAGAIN and keep trying if that happens
            if let Some(token) = self.acquire_allow_interrupts()? {
                return Ok(token);
            }
        }
    }

    /// Waiting for a token in a non-blocking manner, returning `None`
    /// if we're interrupted with EINTR or EAGAIN.
    fn acquire_allow_interrupts(&self) -> io::Result<Option<Acquired>> {
        let mut buf = [0];
        match (&self.read).read(&mut buf) {
            Ok(1) => Ok(Some(Acquired { byte: buf[0] })),
            Ok(_) => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Err(e)
                if e.kind() == io::ErrorKind::Interrupted
                    || e.kind() == io::ErrorKind::WouldBlock =>
            {
                Ok(None)
            }
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

    pub fn pre_run<Cmd>(&self, cmd: &mut Cmd)
    where
        Cmd: Command,
    {
        let read = self.read.as_raw_fd();
        let write = self.write.as_raw_fd();

        let mut fds = Some([read, write]);

        let f = move || {
            // Make sure this function is executed only once,
            // so that the command may be reused with another
            // Client.
            for fd in fds.take().iter().flatten() {
                set_cloexec(*fd, false)?;
            }

            Ok(())
        };

        unsafe { cmd.pre_exec(f) };
    }

    pub fn available(&self) -> io::Result<usize> {
        let mut len = MaybeUninit::<c_int>::uninit();
        cvt(unsafe { libc::ioctl(self.read.as_raw_fd(), libc::FIONREAD, len.as_mut_ptr()) })?;
        Ok(unsafe { len.assume_init() }.try_into().unwrap())
    }
}

#[derive(Debug)]
pub struct Helper {
    thread: JoinHandle<()>,
    shutdown_tx: File,
}

pub(crate) fn spawn_helper(
    client: crate::Client,
    state: Arc<super::HelperState>,
    mut f: Box<dyn FnMut(io::Result<crate::Acquired>) + Send>,
) -> io::Result<Helper> {
    // Create cloexec pipes but not nonblocking, since we would never
    // read from it and we would only write 1 and exactly 1 byte
    // into it.
    let pipes = create_pipe(false)?;

    let mut shutdown_rx = unsafe { File::from_raw_fd(pipes[0]) };
    let shutdown_tx = unsafe { File::from_raw_fd(pipes[1]) };

    let thread = Builder::new().spawn(move || {
        state.for_each_request(|helper| {
            if let Some(res) =
                helper_thread_loop(helper, &client.inner, &mut shutdown_rx).transpose()
            {
                f(res.map(|data| crate::Acquired::new(&client, data)))
            }
        });
    })?;

    Ok(Helper {
        thread,
        shutdown_tx,
    })
}

fn helper_thread_loop(
    helper: &crate::HelperState,
    client: &Client,
    shutdown_rx: &mut File,
) -> io::Result<Option<Acquired>> {
    let fds = [client.read.as_raw_fd(), shutdown_rx.as_raw_fd()];

    loop {
        if helper.producer_done() {
            break Ok(None);
        }

        let (can_acquire, shutdown_requested) = poll_for_readiness2(fds)?;
        if shutdown_requested {
            break Ok(None);
        } else if can_acquire {
            if let Some(acquire) = client.acquire_allow_interrupts()? {
                break Ok(Some(acquire));
            }
        }
    }
}

impl Helper {
    pub fn join(mut self) {
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

        drop(self.thread.join());
    }
}

// start of syscalls

/// Return fds that are nonblocking and cloexec
fn create_pipe(nonblocking: bool) -> io::Result<[RawFd; 2]> {
    let mut pipes = [0; 2];

    // Attempt atomically-create-with-cloexec if we can on Linux,
    // detected by using the `syscall` function in `libc` to try to work
    // with as many kernels/glibc implementations as possible.
    #[cfg(target_os = "linux")]
    {
        static PIPE2_AVAILABLE: AtomicBool = AtomicBool::new(true);
        if PIPE2_AVAILABLE.load(Ordering::Relaxed) {
            let flags = libc::O_CLOEXEC | if nonblocking { libc::O_NONBLOCK } else { 0 };
            match cvt(unsafe { libc::pipe2(pipes.as_mut_ptr(), flags) }) {
                Ok(_) => return Ok(pipes),
                Err(err) if err.raw_os_error() != Some(libc::ENOSYS) => return Err(err),

                // err.raw_os_error() == Some(libc::ENOSYS)
                _ => PIPE2_AVAILABLE.store(false, Ordering::Relaxed),
            }
        }
    }

    cvt(unsafe { libc::pipe(pipes.as_mut_ptr()) })?;

    set_cloexec(pipes[0], true)?;
    set_cloexec(pipes[1], true)?;

    if nonblocking {
        set_nonblocking(pipes[0], true)?;
        set_nonblocking(pipes[1], true)?;
    }

    Ok(pipes)
}

fn set_cloexec(fd: c_int, set: bool) -> io::Result<()> {
    // F_GETFD/F_SETFD can only ret/set FD_CLOEXEC
    let flag = if set { libc::FD_CLOEXEC } else { 0 };
    cvt(unsafe { libc::fcntl(fd, libc::F_SETFD, flag) })?;
    Ok(())
}

fn set_nonblocking(fd: c_int, set: bool) -> io::Result<()> {
    let status_flag = if set { libc::O_NONBLOCK } else { 0 };

    // F_SETFL can only set the O_APPEND, O_ASYNC, O_DIRECT, O_NOATIME, and
    // O_NONBLOCK flags.
    //
    // For pipe, only O_NONBLOCK is meaningful, so it is ok to
    // not issue a F_GETFL fcntl syscall.
    cvt(unsafe { libc::fcntl(fd, libc::F_SETFL, status_flag) })?;

    Ok(())
}

fn dup(fd: c_int) -> io::Result<c_int> {
    cvt(unsafe { libc::dup(fd) })
}

fn dup_with_cloexec(fd: RawFd) -> io::Result<RawFd> {
    static F_DUPFD_CLOEXEC_AVAILBILITY: AtomicBool = AtomicBool::new(true);

    if F_DUPFD_CLOEXEC_AVAILBILITY.load(Ordering::Relaxed) {
        match cvt(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, LOWEST_FD) }) {
            Err(err)
                if err.raw_os_error() == Some(libc::ENOSYS)
                // If the flag F_DUPFD_CLOEXEC is invalid, then it might
                // return EINVAL.
                || err.raw_os_error() == Some(libc::EINVAL) =>
            {
                F_DUPFD_CLOEXEC_AVAILBILITY.store(false, Ordering::Relaxed)
            }
            res => return res,
        }
    }

    // Fallback to dup + set_cloexec
    let new_fd = dup(fd)?;
    set_cloexec(new_fd, true)?;
    Ok(new_fd)
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
fn poll_for_readiness2(fds: [RawFd; 2]) -> io::Result<(bool, bool)> {
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
        let ret = poll(&mut fds, -1)?;
        if ret != 0 {
            break;
        }
    }

    Ok((is_ready(fds[0].revents)?, is_ready(fds[1].revents)?))
}

/// NOTE that this is a blocking syscall, it will block
/// until the fd is ready.
fn poll_for_readiness1(fd: RawFd) -> io::Result<()> {
    let mut fds = [libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }];

    loop {
        let ret = poll(&mut fds, -1)?;
        if ret != 0 && is_ready(fds[0].revents)? {
            break Ok(());
        }
    }
}

fn poll(fds: &mut [libc::pollfd], timeout: c_int) -> io::Result<c_int> {
    cvt(unsafe { libc::poll(fds.as_mut_ptr(), fds.len().try_into().unwrap(), timeout) })
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
