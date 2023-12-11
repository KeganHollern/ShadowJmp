#include <stdint.h>
#include <stdio.h>
#include <Windows.h>

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


extern NTSTATUS create_thread_syscall(uint32_t syscall_id, void* entrypoint, void* argument, OUT PHANDLE hThread);
extern NTSTATUS virtual_alloc_syscall(uint32_t syscall_id, void** address, uint64_t size, uint32_t allocation, uint32_t protection);
extern NTSTATUS virtual_protect_syscall(uint32_t syscall_id, void* address, uint64_t size, uint32_t protection, uint32_t * old);
extern NTSTATUS virtual_query_syscall(uint32_t syscall_id, void* address, PMEMORY_BASIC_INFORMATION buffer, uint64_t length, uint32_t * resultLength);
extern void set_nt_syscall_addr(uint8_t * ntdll_syscall_addr);

HANDLE create_thread(void* entrypoint, void* argument) {
    if (!entrypoint) {
        printf("null entrypoint on createthread call");
        return NULL;
    }

    HANDLE hThread = NULL;

    printf("create_thread(%d, 0x%p, 0x%p, 0x%p);\n",values.create_thread, entrypoint, argument, &hThread);

    NTSTATUS status = create_thread_syscall(values.create_thread, entrypoint, argument, &hThread);
    printf("status: 0x%lx;\n", status);
    if (status < 0) return NULL;

    return hThread;
}

void thread_entry(void* arg) {
    printf("from_thread %d\n", (int)arg);
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

    create_thread(thread_entry, (void*)10);
}
