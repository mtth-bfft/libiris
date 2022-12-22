# Design decisions

The only security boundary supported by operating systems within a user session is between processes: even if, on UNIX operating systems, threads can have different access rights and mitigations, they could easily tamper with each others by writing to their common address space in case of an ASLR leak. Moreover, most security policies on Windows are enforced at the process level.

---> *Each sandboxing policy must be implemented by a dedicated process.*

On Windows, creating a restricted process requires setting specific attributes and pointers in almost all parameters of `CreateProcess`, in a very error-prone way. Moreover, the process memory must be patched before it runs its very basic initialization.

---> *The sandboxing library must offer an API which encapsulates primitives offered by the OS to create processes.*

On Linux, in some cases, modifications must be applied to the seccomp filter of sandboxed processes after they began running.

---> *The sandboxed process must be aware of its sandboxing and cooperate to e.g. load a library.*

On Linux, using `ptrace` or seccomp with `SECCOMP_RET_TRACE` to filter system calls would prevent anyone from attaching to the sandboxed process to debug it (only one debugger can be attached at a time), which would greatly impedes usability of the sandbox by developers.

---> *Linux sandboxing must not rely on `ptrace` or `SECCOMP_RET_TRACE`*

There is no built-in way to track which path is associated with a file descriptor (on Unix) or a handle (on Windows), and tracking in the broker process would open a large attack surface for race conditions and state desynchronisation. Even if such an association was maintained with proper locking in brokers, workers from different brokers could still collaborate to e.g. move files, making their broker table desynchronized with reality.

---> *Operations on file descriptors are allowed unconditionnally, and the only access control possible is at file descriptor opening time. For instance, all system calls like `openat()` on Linux and `NtCreateFile` can only be partially supported, if callers do not use a file-descriptor-relative or handle-relative path*
