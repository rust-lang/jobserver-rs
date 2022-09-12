use std::{
    borrow::Cow,
    convert::TryInto,
    ffi::CString,
    io,
    os::raw::c_void,
    ptr::{self, NonNull},
    sync::Arc,
    thread::{Builder, JoinHandle},
};

use getrandom::getrandom;
use winapi::{
    shared::{
        minwindef::{BOOL, DWORD, FALSE, TRUE},
        winerror::ERROR_ALREADY_EXISTS,
    },
    um::{
        handleapi::CloseHandle,
        synchapi::{
            CreateEventA, ReleaseSemaphore, SetEvent, WaitForMultipleObjects, WaitForSingleObject,
        },
        winbase::{CreateSemaphoreA, OpenSemaphoreA, INFINITE, WAIT_OBJECT_0},
        winnt::{HANDLE, LONG, SEMAPHORE_MODIFY_STATE, SYNCHRONIZE},
    },
};

const WAIT_OBJECT_1: u32 = WAIT_OBJECT_0 + 1;

#[derive(Debug)]
pub struct Client {
    sem: Handle,
    name: String,
}

#[derive(Debug)]
pub struct Acquired;

impl Client {
    pub fn new(limit: usize) -> io::Result<Client> {
        let limit: LONG = limit
            .try_into()
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

        // Note that `limit == 0` is a valid argument above but Windows
        // won't let us create a semaphore with 0 slots available to it. Get
        // `limit == 0` working by creating a semaphore instead with one
        // slot and then immediately acquire it (without ever releaseing it
        // back).
        let create_limit: LONG = if limit == 0 { 1 } else { limit };

        // Try a bunch of random semaphore names until we get a unique one,
        // but don't try for too long.
        for _ in 0..100 {
            let mut bytes = [0; 4];
            getrandom(&mut bytes)?;

            let mut name = format!("__rust_jobslot_semaphore_{}\0", u32::from_ne_bytes(bytes));
            let res = unsafe {
                Handle::new_or_err(CreateSemaphoreA(
                    ptr::null_mut(),
                    create_limit,
                    create_limit,
                    name.as_ptr() as *const _,
                ))
            };

            match res {
                Ok(sem) => {
                    name.pop(); // chop off the trailing nul
                    let client = Client { sem, name };
                    if create_limit != limit {
                        client.acquire()?;
                    }
                    return Ok(client);
                }
                Err(err) => {
                    if err.raw_os_error() == Some(ERROR_ALREADY_EXISTS.try_into().unwrap()) {
                        continue;
                    } else {
                        return Err(err);
                    }
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            "failed to find a unique name for a semaphore",
        ))
    }

    pub unsafe fn open(s: &str) -> Option<Client> {
        let name = CString::new(s).ok()?;

        let sem = OpenSemaphoreA(SYNCHRONIZE | SEMAPHORE_MODIFY_STATE, FALSE, name.as_ptr());
        Handle::new(sem).map(|sem| Client {
            sem,
            name: s.to_string(),
        })
    }

    pub fn acquire(&self) -> io::Result<Acquired> {
        let r = unsafe { WaitForSingleObject(self.sem.0.as_ptr(), INFINITE) };
        if r == WAIT_OBJECT_0 {
            Ok(Acquired)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn release(&self, _data: Option<&Acquired>) -> io::Result<()> {
        let r = unsafe { ReleaseSemaphore(self.sem.0.as_ptr(), 1, ptr::null_mut()) };
        if r != 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn string_arg(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.name)
    }

    pub fn make_inheritable(&self) -> io::Result<crate::utils::MaybeOwned<'_, Self>> {
        // nothing to do here, we gave the name of our semaphore to the
        // child above
        Ok(crate::utils::MaybeOwned::Borrowed(self))
    }
}

#[derive(Debug)]
#[repr(transparent)]
struct Handle(NonNull<c_void>);

impl Handle {
    unsafe fn new(handle: HANDLE) -> Option<Self> {
        NonNull::new(handle).map(Self)
    }

    unsafe fn new_or_err(handle: HANDLE) -> Result<Self, io::Error> {
        Self::new(handle).ok_or_else(io::Error::last_os_error)
    }
}

unsafe impl Sync for Handle {}
unsafe impl Send for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0.as_ptr());
        }
    }
}

#[derive(Debug)]
pub struct Helper {
    event: Arc<Handle>,
    thread: JoinHandle<()>,
}

pub(crate) fn spawn_helper(
    client: crate::Client,
    state: Arc<super::HelperState>,
    mut f: Box<dyn FnMut(io::Result<crate::Acquired>) + Send>,
) -> io::Result<Helper> {
    let event = unsafe {
        let r = CreateEventA(ptr::null_mut(), TRUE, FALSE, ptr::null());
        Handle::new_or_err(r)
    }?;
    let event = Arc::new(event);
    let event2 = Arc::clone(&event);
    let thread = Builder::new().spawn(move || {
        let objects = [event2.0.as_ptr(), client.inner.sem.0.as_ptr()];
        state.for_each_request(|_| {
            let res = match unsafe { WaitForMultipleObjects(2, objects.as_ptr(), FALSE, INFINITE) }
            {
                WAIT_OBJECT_0 => return,
                WAIT_OBJECT_1 => Ok(crate::Acquired::new(&client, Acquired)),
                _ => Err(io::Error::last_os_error()),
            };
            f(res)
        });
    })?;
    Ok(Helper { thread, event })
}

impl Helper {
    pub fn join(self) {
        // Unlike unix this logic is much easier. If our thread was blocked
        // in waiting for requests it should already be woken up and
        // exiting. Otherwise it's waiting for a token, so we wake it up
        // with a different event that it's also waiting on here. After
        // these two we should be guaranteed the thread is on its way out,
        // so we can safely `join`.
        let r = unsafe { SetEvent(self.event.0.as_ptr()) };
        if r == 0 {
            panic!("failed to set event: {}", io::Error::last_os_error());
        }
        drop(self.thread.join());
    }
}
