#include <stdint.h>
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

#include "syscalls.h"

typedef struct syscall_values {
    uint32_t _header;
    // syscalls go below here - do not change order only expand
    uint16_t create_thread;
    uint16_t virtual_alloc;
    uint16_t virtual_protect;
    uint16_t virtual_query;
} syscall_values;

// during injection these values will be overwritten with correct syscall numbers
syscall_values values = {
        0xABCCDEFF,
        199, // kegan is lazy and is hard coding his own syscall numbers
        24,// alloc
        80,// protect
        35,// query
};

extern void set_nt_syscall_addr(uint8_t * ntdll_syscall_addr);


// generic syscall maker
extern NTSTATUS make_syscall(uint32_t syscall_id, uint32_t num_args, ...);

// example implementation of syscaller
NTSTATUS NTAPI NtAllocateVirtualMemory(
        IN HANDLE               ProcessHandle,
        IN OUT PVOID            *BaseAddress,
        IN ULONG                ZeroBits,
        IN OUT PULONG           RegionSize,
        IN ULONG                AllocationType,
        IN ULONG                Protect
) {
    return make_syscall(
            values.virtual_alloc, 6,
            ProcessHandle, BaseAddress, ZeroBits,
            RegionSize, AllocationType, Protect);
}

#include <intrin.h>
#pragma intrinsic(__movsq)

void* copy_test() {
    unsigned __int64 a1[10];
    unsigned __int64 a2[10] = {950, 850, 750, 650, 550, 450, 350, 250,
                               150, 50};

    __movsq(a1, a2, 10);
}

void* get_syscall_addr() {
    char* addr = GetProcAddress(LoadLibraryA("ntdll.dll"),"ZwClearEvent");
    // holy this is so mega lazy
    // this isn't good
    // TODO: actual find pattern
    while(*addr != 0x0F) addr++;
    return addr;
}

void demo_syscall() {
    void* syscall = get_syscall_addr();
    printf("init safe syscall @ 0x%p\n", syscall);
    set_nt_syscall_addr(syscall);


    printf("testing syscall...\n");
    PVOID rb = 0;
    ULONG size = 0x1000;
    NTSTATUS status = NtAllocateVirtualMemory(GetCurrentProcess(), rb, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(NT_SUCCESS(status)) {
        printf("reserved @ 0x%p\n", rb);
    } else {
        printf("alloc failed!");
        exit(2);
    }
}
