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
// TODO:
syscall_values values = {
        0xABCCDEFF,
        199, // kegan is lazy and is hard coding his own syscall numbers
        24,// alloc
        80,// protect
        35,// query
};

extern void set_nt_syscall_addr(uint8_t * ntdll_syscall_addr);
extern void set_rop_gadget(uint8_t * xchg_rsp_r13_addr);
extern void test_rop_gadget();

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

NTSTATUS NTAPI NtCreateThreadEx
        (
                OUT PHANDLE hThread,
                IN ACCESS_MASK DesiredAccess,
                IN PVOID ObjectAttributes,
                IN HANDLE ProcessHandle,
                IN PVOID lpStartAddress,
                IN PVOID lpParameter,
                IN ULONG Flags,
                IN SIZE_T StackZeroBits,
                IN SIZE_T SizeOfStackCommit,
                IN SIZE_T SizeOfStackReserve,
                OUT PVOID lpBytesBuffer) {
    return make_syscall(
            values.create_thread, 11,
            hThread, DesiredAccess, ObjectAttributes,
            ProcessHandle, lpStartAddress, lpParameter,
            Flags, StackZeroBits, SizeOfStackCommit,
            SizeOfStackReserve, lpBytesBuffer);
}

void* get_syscall_addr() {
    char* addr = GetProcAddress(LoadLibraryA("ntdll.dll"),"ZwClearEvent");
    // holy this is so mega lazy
    // this isn't good
    // TODO: actual find pattern
    while(*addr != 0x0F) addr++;
    return addr;
}

void thread_addr(void* param) {
    printf("from a thread! 0x%p\n", param);
}

void demo_syscall() {
    void* syscall = get_syscall_addr();
    printf("init safe syscall @ 0x%p\n", syscall);
    set_nt_syscall_addr(syscall);
    set_rop_gadget((uint8_t*)test_rop_gadget);


    printf("testing syscall...\n");

    // example virtual alloc
    void* base = NULL;
    ULONG size = 0x1000;
    NTSTATUS status = NtAllocateVirtualMemory(
            GetCurrentProcess(), &base, 0, &size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(NT_SUCCESS(status)) {
        printf("memory allocated!: 0x%p\n", base);
    } else {
        printf("memory alloc failed! 0x%lx\n", status);
        exit(3);

    }

    // --- example CreateThread
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(
            &hThread, 0x1FFFFF, NULL,
            GetCurrentProcess(), thread_addr, base,
            0, 0, 0, 0, NULL);
    if(NT_SUCCESS(status)) {
        printf("thread created!\n");
    } else {
        printf("thread failed!  0x%lx.\n", status);
        exit(2);
    }
}
