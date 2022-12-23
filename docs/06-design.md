# Design decisions

The only security boundary supported by operating systems within a user session is between processes: even if, on UNIX operating systems, threads can have different access rights and mitigations, they could easily tamper with each others by writing to their common address space in case of an ASLR leak. Moreover, most security policies on Windows are enforced at the process level.

---> *Each sandboxing policy must be implemented by a dedicated process.*

On Unix systems, most sandboxed programs take an approach where they acquire resources (open files, connect sockets, etc.), setup their process properties (allocate executable memory, etc.), then drop to very low ambient authority. However, on Windows, it is impossible to effectively restrict the ambient authority of an existing process. Moreover, even if it were possible, using this approach risks letting resources leak from the initialization phase (e.g. if a file descriptor to a sensitive resource is kept opened by a library, unaware of its sandboxing).

---> *Sandboxed processes must start in a sandboxed state from their very beginning*

On Windows, creating a restricted process requires setting specific attributes and pointers in almost all parameters of `CreateProcess`, in a very error-prone and developper-unfriendly way. Moreover, the process memory must be patched before it runs its very basic initialization when using some restrictions (e.g. the win32k process mitigation).

---> *The sandboxing library must offer an API which encapsulates primitives offered by the OS to create processes.*

On Linux, if user notifications are not available, some modifications must be applied to the seccomp filter of sandboxed processes after they began running (e.g. to deny calls to `execve`).

---> *The sandboxed process must be aware of its sandboxing and cooperate to e.g. load a library.*

On Linux, using `ptrace` or seccomp with `SECCOMP_RET_TRACE` to filter system calls would prevent anyone from attaching to the sandboxed process to debug it (only one debugger can be attached at a time), which would greatly impedes usability of the sandbox by developers.

---> *Linux sandboxing must not rely on `ptrace` or `SECCOMP_RET_TRACE`*

There are system calls on Unixes (e.g. `openat`) and Windows (e.g. `NtCreateFile`) which take as argument a file descriptor or handle, and a path relative to it. However, there is no built-in way to query the resulting absolute path, and manually tracking the path underlying each file descriptor in the broker process would open a large attack surface for race conditions, state desynchronisation, or collaboration between workers (e.g to move files and desynchronise their broker handle tables with reality).

---> *Policy checks on system calls taking a file descriptor must not try to resolve their file paths, the only policy check on paths must be at file descriptor opening time. System calls taking a file descriptor or handle and a relative path can only be supported if callers pass an already resolved absolute path.*
