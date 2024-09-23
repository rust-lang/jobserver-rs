use std::{env, process::Command};

use jobserver::{Client, FromEnvErrorKind};

fn main() {
    match env::args().skip(1).next().unwrap_or_default().as_str() {
        "" => {
            let me = env::current_exe().unwrap();
            let mut cmd = Command::new(me);
            let client = Client::new(1).unwrap();
            client.configure(&mut cmd);
            drop(client);
            assert!(cmd.arg("from_env").status().unwrap().success());
        }
        "from_env" => {
            let me = env::current_exe().unwrap();
            let mut cmd = Command::new(me);
            let client = unsafe {
                match Client::from_env_ext(true).client {
                    // Its ok for a dropped jobservers path to no longer exist (e.g. on Windows).
                    Err(e) if matches!(e.kind(), FromEnvErrorKind::CannotOpenPath) => return,
                    res => res.unwrap(),
                }
            };
            client.configure(&mut cmd);
            drop(client);
            assert!(cmd.arg("use_it").status().unwrap().success());
        }
        "use_it" => {
            let client = unsafe {
                match Client::from_env_ext(true).client {
                    // See above.
                    Err(e) if matches!(e.kind(), FromEnvErrorKind::CannotOpenPath) => return,
                    res => res.unwrap(),
                }
            };
            client.acquire().unwrap();
        }
        _ => unreachable!(),
    }
}
