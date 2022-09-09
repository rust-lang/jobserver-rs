# jobslot

An implementation of the GNU make jobserver for Rust

[![CI](https://github.com/cargo-bins/jobslot/actions/workflows/main.yml/badge.svg)](https://github.com/cargo-bins/jobslot/actions/workflows/main.yml)

[![Crates.io](https://img.shields.io/crates/v/jobslot.svg?maxAge=2592000)](https://crates.io/crates/jobslot)

[Documentation](https://docs.rs/jobslot)

## Why fork `jobserver`?

 - `jobserver` isn't actively maintained.
 - `jobserver`'s maintainer @alexcrichton is not willing to merge [PR] for
   bug fix.
 - Better performance on unix: `jobserver`'s implementation uses
   [`std::os::unix::process::CommandExt::pre_exec`], which prevents `Command::spawn`
   from using `vfork` on unix.

[PR]: https://github.com/alexcrichton/jobserver-rs/pull/40#issuecomment-1195689752
[`std::os::unix::process::CommandExt::pre_exec`]: https://doc.rust-lang.org/std/os/unix/process/trait.CommandExt.html#tymethod.pre_exec

## Usage

First, add this to your `Cargo.toml`:

```toml
[dependencies]
jobslot = "0.1"
```

# License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in jobslot by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
