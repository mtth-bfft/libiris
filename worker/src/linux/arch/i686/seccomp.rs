use libc::c_int;

pub(crate) const SYSCALL_ASM_OFFSET: usize = 29;

core::arch::global_asm!(
    r#"
.globl rerun_syscall
rerun_syscall:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov eax, DWORD PTR [ebp + 8]  # nb
    mov ebx, DWORD PTR [ebp + 12] # arg0
    mov ecx, DWORD PTR [ebp + 16] # arg1
    mov edx, DWORD PTR [ebp + 20] # arg2
    mov esi, DWORD PTR [ebp + 24] # arg3
    mov edi, DWORD PTR [ebp + 28] # arg4
    mov ebp, DWORD PTR [ebp + 32] # arg5
    int 0x80 # preserves everything except eax
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
"#
);

pub(crate) const SYSCALL_REGISTER_NR: c_int = libc::REG_EAX;
pub(crate) const SYSCALL_REGISTER_A0: c_int = libc::REG_EBX;
pub(crate) const SYSCALL_REGISTER_A1: c_int = libc::REG_ECX;
pub(crate) const SYSCALL_REGISTER_A2: c_int = libc::REG_EDX;
pub(crate) const SYSCALL_REGISTER_A3: c_int = libc::REG_ESI;
pub(crate) const SYSCALL_REGISTER_A4: c_int = libc::REG_EDI;
pub(crate) const SYSCALL_REGISTER_A5: c_int = libc::REG_EBP;
pub(crate) const SYSCALL_REGISTER_IP: c_int = libc::REG_EIP;
pub(crate) const SYSCALL_REGISTER_RET: c_int = libc::REG_EAX;
