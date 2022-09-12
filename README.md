# jobslot

An implementation of the GNU make jobserver for Rust

[![CI](https://github.com/cargo-bins/jobslot/actions/workflows/main.yml/badge.svg)](https://github.com/cargo-bins/jobslot/actions/workflows/main.yml)


[![Crates.io](https://img.shields.io/crates/v/jobslot)](https://crates.io/crates/jobslot)

[Documentation](https://docs.rs/jobslot)

## Why fork `jobserver`?

 - `jobserver`'s maintainer @alexcrichton is not willing to merge [this PR] for
   bug fix because it would change its interface.
 - Better performance on unix: `jobserver`'s implementation uses
   [`std::os::unix::process::CommandExt::pre_exec`], which prevents `Command::spawn`
   from using `vfork` on unix.

[this PR]: https://github.com/alexcrichton/jobserver-rs/pull/40#issuecomment-1195689752
[`std::os::unix::process::CommandExt::pre_exec`]: https://doc.rust-lang.org/std/os/unix/process/trait.CommandExt.html#tymethod.pre_exec

## Other improvements in `jobslot`

 - Remove use of signal handling in the helper thread on unix
 - Use `winapi` on windows instead of manually declaring bindings (some of the bindings seem to be wrong)
 - Use `getrandom` on windows instead of making homebrew one using raw windows api

## Usage

First, add this to your `Cargo.toml`:

```toml
[dependencies]
jobslot = "0.2.4"
```

## Use of this crate in rustc

This crate uses `getrandom` v0.2.7 on windows.
If you want to use this crate in rustc, make sure to bump `getrandom` to v0.2
to avoid pulling in different major versions of the same crate.

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
