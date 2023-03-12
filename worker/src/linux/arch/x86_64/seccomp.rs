use libc::c_int;

pub(crate) const SYSCALL_ASM_OFFSET: usize = 91;

// Trampoline for x86_64 to run a syscall with the given arguments.
// You might be wondering: why code a trampoline in assembly, and not use glibc's
// syscall() function? That's because we need to know from which address the call
// will be made, in order to allow it in seccomp.
core::arch::global_asm!(
    r#"
.globl rerun_syscall
rerun_syscall:
    sub    rsp,0x58
    mov    QWORD PTR [rsp],r9
    mov    r10,r8
    mov    r8,QWORD PTR [rsp]
    mov    QWORD PTR [rsp+0x8],rcx
    mov    rax,rdx
    mov    rdx,QWORD PTR [rsp+0x8]
    mov    QWORD PTR [rsp+0x10],rax
    mov    rax,rsi
    mov    rsi,QWORD PTR [rsp+0x10]
    mov    QWORD PTR [rsp+0x18],rax
    mov    rax,rdi
    mov    rdi,QWORD PTR [rsp+0x18]
    mov    r9,QWORD PTR [rsp+0x60]
    mov    QWORD PTR [rsp+0x28],rax
    mov    QWORD PTR [rsp+0x30],rdi
    mov    QWORD PTR [rsp+0x38],rsi
    mov    QWORD PTR [rsp+0x40],rdx
    mov    QWORD PTR [rsp+0x48],r10
    mov    QWORD PTR [rsp+0x50],r8
    syscall
    mov    QWORD PTR [rsp+0x20],rax
    mov    rax,QWORD PTR [rsp+0x20]
    add    rsp,0x58
    ret
"#
);

pub(crate) const SYSCALL_REGISTER_NR: c_int = libc::REG_RAX;
pub(crate) const SYSCALL_REGISTER_A0: c_int = libc::REG_RDI;
pub(crate) const SYSCALL_REGISTER_A1: c_int = libc::REG_RSI;
pub(crate) const SYSCALL_REGISTER_A2: c_int = libc::REG_RDX;
pub(crate) const SYSCALL_REGISTER_A3: c_int = libc::REG_R10;
pub(crate) const SYSCALL_REGISTER_A4: c_int = libc::REG_R8;
pub(crate) const SYSCALL_REGISTER_A5: c_int = libc::REG_R9;
pub(crate) const SYSCALL_REGISTER_IP: c_int = libc::REG_RIP;
pub(crate) const SYSCALL_REGISTER_RET: c_int = libc::REG_RAX;
