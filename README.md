*Sandboxing* has multiple definitions in the information security field, we use it here to mean reducing your program's *ambient authority* (what it can legitimately do) and the *attack surface* exposed to it (the amount of code it could trigger bugs in, to increase its ambient authority).
This project is intended as a cross-platform sandboxing development harness, with a low barrier to entry. It should help developers who want to inventory which resources their program needs, and split it in coherent chunks (sub-processes) with varying ambient authority. It has not been audited and has not received much community feedback, so *it should not be used for production*.

# Usecase

If the software you develop handles untrusted data (a browser rendering a Web page, a game server taking note of player inputs, etc.), that data may trigger bugs in your code and take over control of your software. If your software is running with the default ambient authority inherited from the user, the attacker has automatically gained access to the user's files and can spy on anything they do. To avoid that, you want to inventory parts of your software most likely to have bugs, and have them run with fewer access rights and fewer accessible APIs. This means you have to simultaneously:
- understand sandboxing goals and methodology;
- get other developers on board, despite their rightful concerns for performance or code complexity;
- change your software architecture to split it into multiple sub-processes, so you have to move to remote procedure calls, sharing state, ensuring proper locking, etc.;
- learn about the different mechanisms offered by the operating system(s) you target, all of which have different APIs, sometimes conflict in their design choices, and sometimes rely on undocumented quirks;
- look at the small volume of documentation of existing projects to see if they fit your needs, then maybe try to integrate them (most complex projects require learning how to use another build system);
- all that before having a working prototype.

The point of this project is to provide both documentation and a development harness to lower the barrier to entry. Hopefully, it can encourage more developers to sandbox their projects and to document common methodologies and solutions.

# Contents

* [docs](docs/): documentation is critical for our goals. If the design or implementation of this library, or the design of OS mechanisms is not clear, open an issue
* [policy](policy/): basically a struct storing the allow-list of everything a sandboxed process is allowed to do
* [broker](broker/): the library which allows creating workers, based on a policy
* [linux-entrypoint](linux-entrypoint/): on Linux only, the very first function executed after fork()ing into a sandboxed process, split off because it needs to be compiled without the Rust standard library (since `fork()` may cut other threads in the middle of their use of the stdlib, we have to assume they were holding a lock and the stdlib is in an unusable state)
* [worker](worker/): the library loaded by all sandboxed processes when they start
* [ipc](ipc/): the library used by workers to send requests to their broker, and receive resources (when allowed)
* [tests](tests/): an integration test suite for all the crates above

# Compilation

You will need:
- on Linux, libseccomp, libcap, and their development package (e.g. `apt install libcap2 libcap-dev libseccomp2 libseccomp-dev`);
- on Windows, Visual Studio (the free Community edition is fine) with the _Desktop C++ Development_ workload;
- [a stable Rust toolchain](https://rustup.rs/);
- a local clone of this repository.

Then a simple `cargo build` should be all it takes (otherwise, open an issue).

# Contributing

Open an issue with a description of any problem you find, or contribute to improving the documentation of sandboxing mechanisms.
If you use this project, feedback would be appreciated (did it help in sandboxing a new software project, was it easy to use, did you face any issue to move to a production-ready sandbox, etc.)
