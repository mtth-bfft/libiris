# Architecture

Each major design decision should be documented here, along with the rationale:

---

Anything implicitly allowed by the library will result in developers not being aware their software needs it to run, and may later need when enforcing restrictions in production.

-> Library should use an [allow-list](/policy), with a deny-by-default approach.

---

The only security boundary supported by operating systems is between processes: even if threads can have different access rights and mitigations applied on Unixes and Windows, they could easily tamper with each others by writing to their common memory address space. Additionally, most APIs that allow setting security policies on Windows work at a process granularity.

-> Each unique sandboxing policy must be implemented by a dedicated process.

---

When creating a child process on Unix systems, a single thread is created in the new child process. Any thread running in parallel in the parent does not exist in the child. Thus if such a thread was using a library and e.g. holding a lock, it may have left the library in an unusable state, and any call to it may hang indefinitely.

-> The first code executed in child processes on Unixes must be compiled [separately](/linux-entrypoint), without using the Rust standard library nor C standard library.

---

On Unixes, validating and filtering system call arguments can be done by using `ptrace`. On Linux, it can also be done using seccomp with `SECCOMP_RET_TRACE`. Both approaches would prevent anyone from attaching to the sandboxed process to debug it (only one debugger can be attached at a time), preventing developpers from debugging their own processes.

-> Unix sandboxing must not rely on `ptrace` nor `SECCOMP_RET_TRACE`.

---

On Windows, creating a process with fewer access rights, and applying specific mitigations (e.g. blocking access to GUI system calls) requires setting specific attributes and pointers in almost all parameters of the process creation API. Moreover, when using some mitigations like blocking access to GUI system calls, the process memory must be patched before it runs its very basic initialization.

-> The sandboxing library must offer an API which encapsulates primitives offered by the OS to create processes.

---

The only [supported security boundary](https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria) usable for sandboxing for Windows is AppContainers.

-> Use AppContainers on Windows.
