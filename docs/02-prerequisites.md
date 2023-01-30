# Prerequisites

Designing a project to be sandboxed, or retrofitting a sandbox in an existing project, are time consuming projects with lots of implications. Before diving in it, one should review existing mitigation techniques in compile-time, link-time or run-time hardening which may give a better return on time invested.

## Programming language

When starting a project from scratch, it might be worthwhile to take the time to find a programming language with the appropriate abstraction level and security guarantees that mitigate vulnerability classes most likely to be exploited. For instance, Rust provides strong memory and concurrency guarantees[27], but can be complex to learn and use.

## Dependency and patch management

Using a code versionning tool like Git can give insights into how many people maintain each part of a codebase. Parts with too few maintainers for their complexity can be prioritized, simplified, or replaced with external libraries.
Likewise, dependencies to third-party libraries need to be reviewed: are they the root cause of security vulnerabilities in your project, or do they take a long time to be updated (especially when vulnerabilities are found)? If so, looking for an equivalent library could be worthwhile.

## Priorization

Introducing sandboxing comes at a cost (development and maintenance time, and performance overhead at runtime), so you should prioritize and start with your most sensitive applications. Depending on your attack scenarios, this could be e.g. a server exposed to a large network, or a document parser running on a host containing sensitive data.

When doing this inventory, keep in mind that every application you manage to remove from this list is a lot of time and effort saved. Sandboxing is way more costly than e.g. reducing network exposure, or moving sensitive data to other hosts and isolating the untrusted host at the network level.

## Static code analysis and additional compiler verifications

Using an up-to-date compiler is often sufficient to warn developers if they use legacy functions which do not check their parameters sufficiently (e.g. `strcpy`, `sprintf`), or are otherwise common sources of vulnerabilities. This is done by default by MSVC since at least Microsoft Visual Studio 2008 (just ensure `_CRT_SECURE_NO_WARNINGS` is not defined)[8][9]. Additional checks should be enabled, e.g. using the `/sdl` and `/W4` flag for the MSVC compiler[2], and the `-Wall`, `-Wextra`, `-pedantic` for the GNU C Compiler[21].

Compilers can automatically insert run-time checks for data truncation, uninitialized variable use, buffer overruns and underruns, etc. For instance, MSVC can do it with the `/RTCcsu` flag but on debug builds only[5], and the `-D_FORTIFY_SOURCE=2` flag should be enabled when using the GNU C Compiler (make sure you also enable optimisations with `-O1` or higher)[21].

Using linter tools can warn developers of additional poor coding patterns (e.g. lack of error checking, missing documentation, etc.), and some compilers support additional non-standard annotations like Microsoft's Source-code Annotation Language[1][15]. If the codebase needs to be compiled for multiple platforms using multiple compilers, it is possible to use such annotations on one platform only, and define them to be erased during precompilation on other platforms.

## Compile-time and link-time mitigation options

Various mitigations can be enforced by compilers and linkers. Some open-source tools allow checking an executable's effective mitigations, e.g. checksec[13] for ELF, and winchecksec[14] for PE files. They can be run automatically in a continuous test pipeline to report any regression.

### Stack buffer overflow protection

One of the most common vulnerabilities lies in weak bounds checking when reading data of attacker-controlled length into a shorter buffer on the stack. If a return address, a function pointer, a C++ reference, or a longjmp structure lies after the buffer, this can lead to arbitrary code execution (if only data variables can be overwritten, this may still allow modifying the program's logic). In many cases this can be prevented by setting a **canary**[7] at the end of buffers, with a value unpredictable by attackers, checked before returning from the function: if the values does not match what was written, it means an overflow occured and execution is halted. Additionnally, to prevent overwriting local variables in the stack frame, buffers can be reordered last on the stack, and copying parameters before buffers in the function prologue (this still does not protect against overflows within a structure)[10].

The GNU Compiler Collection (GCC) offers `-fstack-protector` [11] (which only protects functions with certain heuristics) and `-fstack-protector-all` (which protects all functions). The newer `-fstack-protector-strong` should at least be used, as a a trade-off between the two[12]. Visual Studio also implements such a mitigation by default since 2005 for functions which contain stack buffers and a certain number of heuristics[10]: just ensure optimizations are enabled for release builds, the `/GS-` flag is not set, and no custom entry point is set.

### Non-executable memory

Modern processors support making memory pages executable or not, a feature called "No Execute" (NX), "Execute Disable" (XD), or other names depending on manufacturers. This restricts where attackers can write malicious payloads for later execution: for instance, both stack and heap may contain attacker-controlled data, but both have no reason to be executable. This processor feature is used by modern operating systems when mapping sections of an executable file into memory, under the condition that the executable file indicates that it is compatible.

Since Linux 2.6.8, for the ELF format, this is done by marking the stack (the ELF segment with a `PT_GNU_STACK` type[29]) as non-executable. An executable stack or the absence of a stack segment, on some CPU architectures or kernels before version 5.4[31], make the kernel switch on the `READ_IMPLIES_EXEC` personality flag[30] for the entire process, making all its data allocations executable. During linking, a single object file without this flag (e.g. a simple assembly file, even empty) will remove the flag from the final executable, thus to guarantee this does not happen the `-z noexecstack` flag should be used with the GNU C Compiler.

All Windows versions enforce this behaviour for their 64-bit processes[33]. Since Windows XP and Server 2003, compatibility for 32-bit Portable Executable files is indicated by a `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` flag in their header, which can be set since Visual Studio 2005 SP1 using the `/NXCOMPAT` linker option[35]. The Active Template Library (ATL) up to version 7.1 tried to execute code in data sections, so specific code handles page faults when they originate in that library. This compatibility layer can be disabled by calling `SetProcessDEPPolicy(PROCESS_DEP_ENABLE|PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION)` at runtime[34].

### Address Space Layout Randomisation

When non-executable data is enforced, attackers can only reuse code already in the address space of their target. To prevent attackers from overwriting a function pointer and call functions of their choosing, Address Space Layout Randomisation (ASLR) mitigations make the base address of code segments unpredictable by attackers. Data segments are also randomized, since they often contain function pointers which would leak code segment base addresses.

The randomization of library base addresses, stack and dynamically allocated memory is done automatically on Linux since version 2.6.12, with stronger implementations on more modern versions. Some memory segments (e.g. the Process Environment Block) are randomized on Windows since Windows XP, and executables (programs and libraries) can be randomized along with their stacks and heaps since Windows Vista and Windows Server 2008, if they have the `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` flag in their headers, which can be set since Visual Studio 2005 with the `/DYNAMICBASE` option[38] and is on by default since Visual Studio 2010[39].

On Windows, unlike Linux, library and executable base addresses are randomized once per boot, by randomly picking a global random number at each boot and deriving all code segment addresses from it.[37]

On Linux, by default, compilers produce executable files whose base address is fixed for performance reasons, which allows attackers to know in advance the address of some functions and code fragments. Linking the executable itself as a shared object instead ("Position Independent Executable", PIE, or "full ASLR") produces an ELF with a `ET_DYN` object type instead of `ET_EXEC`, allowing it to benefit from ASLR too. This should be done, with the `-fPIE -pie` options.

To fully benefit from ASLR, code should be compiled for 64-bit hardware, which gives orders of magnitude more entropy to randomized addresses. On Windows, the additional `/HIGHENTROPYVA` option is required to fully benefit from it since Windows 8 and Visual Studio 2012[38].

Of course, all these mitigations are broken if the application (or one of its dependencies) dynamically allocates memory at a fixed address (e.g. using `mmap()` on Linux or `VirtualAlloc` on Windows with a requested fixed address), so this might require a code review.

### Safe Exception Handlers

On Windows, the *Structured Exception Handling* (SEH) non-standard C extension allows developers to handle hardware and software exceptions without crashing, using the `__try` instruction[17]. When compiling for x86, addresses of exception handlers are stored in the stack next to return addresses, so that if an exception happens in a nested function call, the system can unwind the stack until it finds a handler which knows how to handle that type of exception. Thus, a common way to bypass stack buffer overflow protection is to overwrite the SEH handler address on the stack and trigger an exception (e.g. by dereferencing invalid memory) before the function returns and finds out its canary has been overwritten[18]. This does not apply to x64 and AMD targets, where exception handlers are inventoried in a separate section of the executable.

To prevent this, Visual Studio 2003 introduced the `/SAFESEH` linker flag, which enforces each input object to contain a list of all authorized exception handlers in its metadata[19] (a previous weaker form, called "Software-enforced DEP", only verified that the handler lied in an executable page[32]). This way, before transferring control to an exception handler, the list can be checked and stack unwinding can be interrupted if an unknown handler is found. This mitigation is a good practice, but loading any library not compiled with it makes the entire process vulnerable: all the attacker has to do is register a handler pointing to well-chosen instructions within that module, which will transfer control to arbitrary code.

To handle cases where third-party modules might be loaded and lessen the protection offered by SafeSEH, Windows Vista and Windows Server 2008 introduced a mechanism called *Structured Exception Handler Overwrite Protection* (SEHOP), which validates that the exception chain ends with a well-known handler, and if not, no handler is executed at all[16]. The address of that handler is within ntdll.dll and needs to be unpredictable, thus SEHOP is only as strong as ASLR: if an attacker can guess the correct address, they can build a fake exception handler chain and bypass the check[20]. This mitigation is enabled by default on server editions since 2008, and available but disabled on client editions since Vista SP1. If the application to protect is installed with administrative rights, the installer can, however, enable this mitigation just for the application by creating the following registry value:

    reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\replace_your_app_name_here.exe /v DisableExceptionChainValidation /t DWORD /d 0

### Stack clash protection

A class of vulnerability consists in exploiting the fact that stacks expand in memory without making a specific request to the kernel: when they need more memory, they just start using their *guard page* (one page without write permissions, mapped just next to the stack), which generates a page fault. However, if a function allocates more than one page at a time, and does not use memory in the guard page, it can unwillingly start overwriting segments next to its stack (the heap, an anonymous memory mapping, or a data section). The stack can overwrite data from other segments (e.g. changing application-specific variables), or get overwritten by them (e.g. changing a return address without destroying the stack cookie). This attack is exploitable in applications using attacker-controlled variable-length arrays[23], `alloca()` stack allocations[24], or if an attacker can trigger many recursive calls, or control environment variables or commandline arguments, or can gradually leak memory to force allocations to happen near the stack[22]. It can be exploited in two ways: both to overwrite data sections with memory coming from the stack, or to overwrite the stack (e.g. a return address) with data coming from other allocations.

This class of vulnerability can be mitigated using stack probing: when allocating local variables across more than one stack page, at least one byte is written to each page. This is enabled by default since Visual Studio 2005[6] (just ensure /Gs is not set, or set to a value lower or equal to the page size of the system), and should be enabled with the `-fstack-clash-protection` when using the GNU C Compiler[36]

### Link-time hardening

When using a global variable or calling a function exported by a shared object, the compiler lets a blank space (a relocation) for the address of that symbol, and the loader fills that blank with the runtime (randomized) address. To avoid patching code sections, which would prevent processes from sharing the same memory pages, relocations are done in an intermediary table of pointers, at a known offset from the code so it can be dereferenced. For unresolved data, pointers are stored in the Global Offset Table (GOT). For unresolved functions, calls are made to stubs generated by the linker in a Procedure Linkage Table (PLT) at a fixed offset, and these stubs just jump to pointers stored in the GOT. In both cases, since these pointers are resolved at runtime, they are writable and can be overwritten to convert a memory corruption into an arbitrary code execution. To prevent this, the GNU linker supports the `-Wl,-z,relro` option which adds the `PT_GNU_RELRO` flag to various sections (.ctors, .dtors, .jcr, .dynamic, .got, or others depending on the architecture), so that they are remapped as read-only after relocations have been processed.

However, dynamic loading of symbols is performed lazily by default, meaning the GOT remains writable and each symbol is only resolved when its address is actually required. To force symbols to be resolved at program startup or at library load time, the `-Wl,-z,now` option must also be used.[40]

Finally, enabling the `--as-needed` and `-flto` options when using the GNU or LLVM linker may avoid linking unused symbols (or even entire libraries) in the final executable. This may reduce the amount of code available to an attacker to misuse (e.g. to find gadgets when building a ROP exploit).

### Control Flow Integrity (CFI)

To prevent reuse of existing code in unexpected ways, control flow can be explicitly restricted to only those code paths expected at link time.

Clang supports checking that pointers to code are actual addresses of functions before jumping to them or calling them ("forward-edge CFI"), when enabling the `-fsanitize=cfi` option[41]. MSVC supports the `/CETCOMPAT` option in Visual Studio 2019 and newer, to use the Intel-specific CET Shadow Stack feature.

## Unit and integration tests

To find existing bugs and minimize the number of new ones introduced in the future, it is always a good idea to build a test harness around a codebase. Tests are useful for short pieces of code (**unit tests**) and for their interaction with other parts (**integration tests**), both for testing that they work as intended and that they fail early and gracefully in case of errors. **Code coverage** tools exist which can assist in finding any safety-critical code path not covered by any test[25].

Various **sanitizer** tools (e.g. `-fsanitize` integrated to LLVM[26] and MSVC) can enforce stricter runtime checks by instrumenting executables, to detect errors which would otherwise not cause an immediate visible effect.

In addition to tests, a **fuzzer** can feed randomly generated inputs and try to trigger more code paths, in ways developers did not expect and thus for which they did not write tests.[28]

## References

    [1] https://docs.microsoft.com/en-us/cpp/code-quality/understanding-sal
    [2] https://docs.microsoft.com/en-us/cpp/build/reference/sdl-enable-additional-security-checks
    [5] https://docs.microsoft.com/en-us/cpp/build/reference/rtc-run-time-error-checks
    [6] https://docs.microsoft.com/en-us/cpp/build/reference/ge-enable-stack-probes
    [7] https://web.archive.org/web/20130309083252/http://tmp-www.cpe.ku.ac.th/~mcs/courses/2005_02/214573/papers/buffer_overflows.pdf
    [8] https://docs.microsoft.com/en-us/cpp/c-runtime-library/security-features-in-the-crt
    [9] https://docs.microsoft.com/en-us/cpp/c-runtime-library/parameter-validation
    [10] http://msdn.microsoft.com/en-us/library/8dbf701c(VS.80).aspx
    [11] https://gcc.gnu.org/onlinedocs/gcc-4.1.2/gcc/Optimize-Options.html#Optimize-Options
    [12] https://gcc.gnu.org/legacy-ml/gcc-patches/2012-06/msg00974.html
    [13] https://github.com/slimm609/checksec.sh
    [14] https://github.com/trailofbits/winchecksec
    [15] https://docs.microsoft.com/en-us/cpp/code-quality/quick-start-code-analysis-for-c-cpp
    [16] http://web.archive.org/web/20100329234458/http://blogs.technet.com/srd/archive/2009/02/02/preventing-the-exploitation-of-seh-overwrites-with-sehop.aspx
    [17] https://docs.microsoft.com/en-us/windows/win32/debug/frame-based-exception-handling
    [18] Litchfield, David. Defeating the Stack Based Buffer Overflow Prevention Mechanism of Microsoft Windows 2003 Server. Sep, 2003. http://web.archive.org/web/20101214045946/http://www.ngssoftware.com/papers/defeating-w2k3-stack-protection.pdf
    [19] Microsoft Corporation. /SAFESEH (Image has Safe Exception Handlers). https://docs.microsoft.com/en-us/cpp/build/reference/safeseh-image-has-safe-exception-handlers
    [20] Le Berre, Stéfan. Bypassing SEHOP. https://www.exploit-db.com/download/15379
    [21] Debian. Hardening. https://wiki.debian.org/Hardening
    [22] Qualys. The Stack Clash. https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
    [23] Exodus Intelligence. DoS? Then Who Was Phone? http://blog.exodusintel.com/2013/01/07/who-was-phone/
    [24] Griffiths, Andrew. Clutching at straws: When you can shift the stack pointer. http://phrack.org/issues/63/14.html
    [25] Glenford J. Myers. The Art of Software Testing, 2nd edition
    [26] Sanitizers. Google. https://github.com/google/sanitizers/
    [27] Exploit Mitigations. Rust. https://doc.rust-lang.org/rustc/exploit-mitigations.html
    [28] Automated Penetration Testing with White-Box Fuzzing. John Neystadt. https://docs.microsoft.com/en-us/previous-versions/software-testing/cc162782(v=msdn.10)
    [29] Format of Executable and Linking Format (ELF) Files. Michael Kerrisk. https://man7.org/linux/man-pages/man5/elf.5.html
    [30] Personality. Michael Kerrisk. https://man7.org/linux/man-pages/man2/personality.2.html
    [31] https://patchwork.kernel.org/project/linux-arm-kernel/patch/20190424203408.GA11386@beast/
    [32] https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-xp/bb457155(v=technet.10)
    [33] https://devblogs.microsoft.com/cppblog/dynamicbase-and-nxcompat/
    [34] https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setprocessdeppolicy
    [35] https://docs.microsoft.com/en-us/cpp/build/reference/nxcompat-compatible-with-data-execution-prevention
    [36] https://developers.redhat.com/blog/2020/05/22/stack-clash-mitigation-in-gcc-part-3#
    [37] https://web.archive.org/web/20190715102700/http://www.symantec.com/avcenter/reference/Address_Space_Layout_Randomization.pdf
    [38] https://msrc-blog.microsoft.com/2013/12/11/software-defense-mitigating-common-exploitation-techniques/
    [39] https://msrc-blog.microsoft.com/2017/11/21/clarifying-the-behavior-of-mandatory-aslr/
    [40] https://wiki.gentoo.org/wiki/Hardened/Toolchain
    [41] https://clang.llvm.org/docs/ControlFlowIntegrity.html

