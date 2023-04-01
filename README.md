libiris
=======

| Build | Tests                      |
|-------|----------------------------|
| ![Linux](https://gitlab.com/libiris/libiris/badges/main/pipeline.svg?ignore_skipped=true&style=flat-square&job=build_linux&key_text=Linux&key_width=60) | ![Debian 11](https://gitlab.com/libiris/libiris/badges/main/pipeline.svg?ignore_skipped=true&style=flat-square&job=test_linux&key_text=Debian%2011&key_width=70) |
| ![Windows](https://gitlab.com/libiris/libiris/badges/main/pipeline.svg?ignore_skipped=true&style=flat-square&job=build_windows&key_text=Windows&key_width=60) | ![7 SP1](https://gitlab.com/libiris/libiris/badges/main/pipeline.svg?ignore_skipped=true&style=flat-square&job=test_win7_x64&key_text=7%20SP1&key_width=70)&nbsp;&nbsp;![7 SP1](https://gitlab.com/libiris/libiris/badges/main/pipeline.svg?ignore_skipped=true&style=flat-square&job=test_win10_latest_x64&key_text=10%2022H2&key_width=70) |

libiris is a cross-platform sandboxing harness. This project is not a production-ready sandboxing library, instead it aims at being a good development harness for codebases which need modifications or testing in preparation for sandboxing.

Sandboxing means reducing your program's *ambient authority* (what it can legitimately do) and the *attack surface* exposed to it (the amount of code it can trigger bugs in, to increase its ambient authority). This requires understanding internals about each OS and platform your project targets, and requires splitting your program into multiple processes (for reasons detailed in the [docs](./docs/)). This takes a lot of time and effort, and has no user-visible added value on the short term. The goal of this project is to reduce entry costs, so that more developers try to sandbox their projects, and to document common solutions, so that developers without a security background are incentivized to reuse them instead of starting from scratch.

This repository contains:

* `docs`: documentation is critical for our goals. If the design or implementation of this library, or the design of OS mechanisms is not clear, open an issue
* `worker`: the library loaded by sandboxed processes (*workers*) when they start
* `policy`: a crate to specify exactly what a worker can do
* `broker`: the library which allows creating workers, based on a policy
* `ipc`: a crate which allows workers to send requests to their broker, and receive resources (when allowed)
* `linux-entrypoint`: the very first function executed by Linux workers when they start, split off because it needs to be compiled without the Rust standard library (which may be in an inconsistent state after a `fork()`, e.g. due locks held by threads which do not exist anymore)
* `tests`: an integration test suite for all the crates above

# Compilation

You will need:
- a stable Rust toolchain;
- on Linux, libseccomp, libcap, and their development package (e.g. `apt install libcap2 libcap-dev libseccomp libseccomp-dev` if you are running Debian);
- this repository.

Then a simple `cargo build` should be all it takes (otherwise, open an issue).

# Contributing

If you use this project, feedback would be appreciated (to sandbox what, on what kinds of platforms, was something hard to grasp, did you face any integration issue, etc).

Even if you do not use the project, you can help with code reviews and documentation reviews (especially about design choices and OS isolation internals).
