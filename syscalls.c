#include <stdint.h>
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

#include "syscalls.h"

// TODO: gather these dynamically or from some
//  syscall helper
syscall_values values = {
    .create_thread = 199,
    .virtual_alloc = 24,
    .virtual_protect = 80,
    .virtual_query = 35,
    .set_windows_hook_ex = 4228,
    .get_user_message = 4100,
};

// ASM functions for setup
extern void set_nt_syscall_addr(uint8_t * ntdll_syscall_addr);
extern void set_rop_gadget(uint8_t * xchg_rsp_r13_addr);
extern void test_rop_gadget();

void* get_syscall_addr() {
    char* addr = GetProcAddress(LoadLibraryA("ntdll.dll"),"ZwClearEvent");
    // holy this is so mega lazy
    // this isn't good
    // TODO: actual find pattern
    while(*addr != 0x0F) addr++;
    return addr;
}

void init_syscalls() {
    void* syscall = get_syscall_addr();
    printf("init safe syscall @ 0x%p\n", syscall);
    set_nt_syscall_addr(syscall);
    set_rop_gadget((uint8_t*)test_rop_gadget);
}
