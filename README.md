libiris
=======

![Build Status](https://github.com/mtth-bfft/libiris/actions/workflows/build_test.yml/badge.svg?branch=main)

libiris is a (work in progress) cross-platform sandboxing library.

This repository contains:

* `broker`: the broker library which allows creating workers
* `worker`: the worker library loaded by workers when they start
* `policy`: a crate which allows specifying exactly what rights a worker has
* `ipc`: a crate which allows workers to send requests to their broker, and get resources in response
* `tests`: an integration test suite for all the crates above

# Compilation

You will need:
- a stable Rust toolchain;
- libseccomp and its development headers (e.g. `apt install libseccomp libseccomp-dev` if you are running Debian)

Then a simple `cargo build` should be all it takes.
