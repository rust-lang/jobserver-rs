//! The jobserver can also be used as a synchronisation primitive for shared
//! resources.
//!
//! By populating the jobserver with unique tokens, we can provide a reference
//! to a single instance of a shared resource.
extern crate jobserver;

#[cfg(unix)]
pub mod imp {
    use std::sync::mpsc::channel;
    use std::sync::Arc;
    use std::thread;
    use std::time;

    use jobserver::Client;

    fn sleep() {
        thread::sleep(time::Duration::from_millis(500));
    }

    /// Run some number of jobs in parallel, limited by the number of tokens.
    fn do_jobs_with_tokens(jobs: usize, tokens: u8) {
        println!("");
        println!("Running {} jobs with {} resources:", jobs, tokens);
        let now = time::Instant::now();

        let jobserver =
            Arc::new(Client::new_with_unique(tokens).expect("Couldn't create jobserver."));

        // Spawn jobs in new threads, but limit by acquiring tokens.
        let (tx, rx) = channel();
        for job_number in 0..jobs {
            let (jobserver, tx) = (Arc::clone(&jobserver), tx.clone());
            thread::spawn(move || {
                let token = jobserver.acquire().expect("Couldn't acquire token.");
                println!(
                    "Job {} is using resource {}.",
                    job_number,
                    token.data().byte()
                );
                sleep();
                tx.send(()).unwrap();
            });
        }

        // Collect jobs
        for _ in 0..jobs {
            rx.recv().unwrap();
        }
        println!("Execution took: {}ms", now.elapsed().as_millis());
    }

    pub fn run() {
        do_jobs_with_tokens(6, 1);
        do_jobs_with_tokens(6, 2);
        do_jobs_with_tokens(6, 6);
    }
}

#[cfg(not(unix))]
pub mod imp {
    pub fn run() {
        println!("This example is only supported on unix platforms.");
    }
}

fn main() {
    imp::run();
}
