libiris
=======

![Build Status](https://github.com/mtth-bfft/libiris/actions/workflows/build_test.yml/badge.svg?branch=main)

libiris is a (work in progress) cross-platform sandboxing library. This project is not a production-ready sandbox, instead it aims at being a good development harness for codebases which need modifications for sandboxing.

Sandboxing means reducing your program's *ambient authority* (what it can legitimately do) and the *attack surface* exposed to it (the amount of code it can trigger bugs in, to escape the sandbox). This requires understanding internals about each OS your program supports, and requires splitting your program into multiple processes (for reasons detailed in the [docs](./docs/)). This takes a lot of time and effort, and has no any user-visible added value. The goal of this project is to reduce entry costs, so that more developers try to sandbox their projects, and to document common solutions, so that developers without a security background are incentivized to reuse them.

This repository contains:

* `docs`: documentation is critical for our goals. If the design or implementation of this library, or the design of OS mechanisms is not clear, open an issue
* `worker`: the library loaded by sandboxed processes (*workers*) when they start
* `policy`: a crate to specify exactly what a worker can do
* `broker`: the library which allows creating workers, based on a policy
* `ipc`: a crate which allows workers to send requests to their broker, and get resources in response
* `tests`: an integration test suite for all the crates above

# Compilation

You will need:
- a stable Rust toolchain;
- libseccomp and its development package (e.g. `apt install libseccomp libseccomp-dev` if you are running Debian);
- this repository.

Then a simple `cargo build` should be all it takes.

# Contributing

If you try to use this project, feedback would be appreciated (to sandbox what, in what kinds of environments, did you face any issue, etc).

Even if you do not use the project, code reviews, documentation reviews (especially about design choices and OS isolation internals) is always welcome.
