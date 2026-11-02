#[cfg(unix)]
fn main() {
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::process::Command;

    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--read-token") {
        let read: i32 = args[2].parse().unwrap();
        let write: i32 = args[3].parse().unwrap();
        let mut token = 0u8;
        // SAFETY: the initialized byte is live for the syscall. Invalid/closed descriptors
        // return an OS error; no Rust ownership is taken from the numeric descriptor.
        let count = unsafe { libc::read(read, (&mut token as *mut u8).cast(), 1) };
        if count == 1 {
            println!("token={token}");
            if token == b'|' {
                // SAFETY: same one-byte buffer; the test jobserver's write end is inherited.
                assert_eq!(
                    unsafe { libc::write(write, (&token as *const u8).cast(), 1) },
                    1
                );
            }
        } else {
            println!("closed");
        }
        return;
    }

    struct TestDir(std::path::PathBuf);
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let name = format!(
        "jobserver-configure-lifetime-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    std::fs::create_dir(&path).unwrap();
    let dir = TestDir(path);
    let first_path = dir.0.join("first-canary");
    let second_path = dir.0.join("second-canary");
    std::fs::write(&first_path, b"first test canary").unwrap();
    std::fs::write(&second_path, b"second test canary").unwrap();

    for configure_make in [false, true] {
        let client = jobserver::Client::new(1).unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        if configure_make {
            client.configure_make(&mut command);
        } else {
            client.configure(&mut command);
        }
        let flags = command
            .get_envs()
            .find(|(name, _)| *name == "CARGO_MAKEFLAGS")
            .unwrap()
            .1
            .unwrap()
            .to_str()
            .unwrap();
        let auth = flags
            .split_whitespace()
            .find_map(|arg| arg.strip_prefix("--jobserver-auth="))
            .unwrap()
            .to_owned();
        let (read, write) = auth.split_once(',').unwrap();
        command.args(["--read-token", read, write]);

        // The command must own its descriptors even after the original Client is dropped.
        // Before the fix these opens reuse them, and pre_exec makes unrelated files inheritable.
        drop(client);
        let first = File::open(&first_path).unwrap();
        let second = File::open(&second_path).unwrap();
        let mut control = Command::new(std::env::current_exe().unwrap());
        control.args([
            "--read-token",
            &first.as_raw_fd().to_string(),
            &second.as_raw_fd().to_string(),
        ]);
        let result = control.output().unwrap();
        assert!(result.status.success());
        assert_eq!(String::from_utf8(result.stdout).unwrap().trim(), "closed");

        // A configured command may be spawned more than once. Both spawns must still inherit
        // the jobserver token, and neither may see one of the unrelated canary files.
        for _ in 0..2 {
            let result = command.output().unwrap();
            assert!(result.status.success(), "{:?}", result);
            assert_eq!(
                String::from_utf8(result.stdout).unwrap().trim(),
                "token=124"
            );
        }
    }
}

#[cfg(not(unix))]
fn main() {}
