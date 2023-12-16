#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include <Windows.h>
#include <winternl.h>
#include <winnt.h>
#include <DbgHelp.h>

#include "instrumentation.h"

// More info: https://winternl.com/detecting-manual-syscalls-from-user-mode/

typedef NTSTATUS (NTAPI *nt_set_information_process_t)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);
typedef void (*bridge_function_t)();
struct process_instrumentation_callback_info_t {
    uint32_t version;
    uint32_t reserved;
    bridge_function_t callback;
};

void PrintStackAI(CONTEXT* pCtx) {
    if (pCtx == NULL) {
        printf("Context is null\n");
        return;
    }

    HANDLE process = GetCurrentProcess();
    DWORD thread = GetCurrentThreadId();

    const int maxFrames = 20;
    void* RIP = (void*)pCtx->Rip;
    void* RSP = (void*)pCtx->Rsp;

    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;

    char full_print_buffer[(MAX_SYM_NAME * sizeof(TCHAR) + 32) * maxFrames];
    int push = 0;

    void** pStack = (void**)RSP;
    for (int i = -1; i < maxFrames; i++) {
        void* returnTo = (i == -1) ? RIP : pStack[i];
        //if (returnTo == NULL) break;

        DWORD64 displacement = 0;
        if (returnTo && SymFromAddr(process, (DWORD64)returnTo, &displacement, pSymbol)) {
            push += sprintf(&(full_print_buffer[push]), "\t[%lu] stack[%d]: 0x%p %s\n", thread, i + 1, returnTo, pSymbol->Name);
        } else {
            push += sprintf(&(full_print_buffer[push]), "\t[%lu] stack[%d]: 0x%p\n", thread, i + 1, returnTo);
        }
    }
    full_print_buffer[push] = '\0';
    printf("STACK DUMP:\n%s", full_print_buffer);
}

extern void bridge(); // ASM bridge for stack setup
volatile DWORD tlsIndex = 0;

bool* get_thread_data_ptr() {
    void* thread_data = TlsGetValue(tlsIndex);

    if(!thread_data) {
        thread_data = LocalAlloc(LPTR, 256);
        if(!thread_data) return NULL;

        RtlZeroMemory(thread_data, 256);

        if(!TlsSetValue(tlsIndex, thread_data)) return NULL;
    }

    return (bool*)thread_data;
}
bool is_thread_handling_syscall() {
    bool* data_ptr = get_thread_data_ptr();
    if(!data_ptr) return false;
    return *data_ptr;
}
bool set_thread_handling_syscall(bool value) {
    bool* data_ptr = get_thread_data_ptr();
    if(!data_ptr) return false;
    *data_ptr = value;
    return true;
}

void callback(CONTEXT* ctx) {
    uint64_t teb = (uint64_t)NtCurrentTeb();

    // Grab and store the address we should return to.
    ctx->Rip = *(uint64_t*)(teb + 0x02d8);
    // Grab and store the stack pointer that we should restore.
    ctx->Rsp = *(uint64_t*)(teb + 0x02e0);
    // Recover original RCX.
    ctx->Rcx = ctx->R10;



    // if we're handling a syscall, abort
    if(is_thread_handling_syscall()) {
        RtlRestoreContext(ctx, NULL);
        return;
    }

    // if we fail to set the TLS variable, abort
    if(!set_thread_handling_syscall(true)) {
        RtlRestoreContext(ctx, NULL);
        return;
    }

    // print the callstack for callback
    PrintStackAI(ctx);

    set_thread_handling_syscall(false);
    RtlRestoreContext(ctx, NULL);
}

void init_callbacks() {
    // initialize DbgHelp
    SymSetOptions(SYMOPT_UNDNAME);
    SymInitialize(GetCurrentProcess(), NULL, TRUE);

    HANDLE hNTDll = LoadLibraryA("ntdll.dll");
    if(!hNTDll) {
        printf("failed to load ntdll");
        exit(1);
    }

    nt_set_information_process_t nt_set_information_process = (nt_set_information_process_t)GetProcAddress(hNTDll, "NtSetInformationProcess");
    if(!nt_set_information_process) {
        printf("failed to find NtSetInformationProcess");
        exit(1);
    }

    tlsIndex = TlsAlloc();
    if(tlsIndex == TLS_OUT_OF_INDEXES) {
        printf("could not allocate TLS index");
        exit(1);
    }

    struct process_instrumentation_callback_info_t info;
    info.version = 0;  // x64 mode
    info.reserved = 0;
    info.callback = bridge;

    printf("setting instrumentation callbacks...\n");

    NTSTATUS status = nt_set_information_process(GetCurrentProcess(),
                                                 (PROCESS_INFORMATION_CLASS)(0x28),
                                                 &info, sizeof(info));

    if(!NT_SUCCESS(status)) {
        printf("failed to set callback");
        exit(1);
    }

    printf("callbacks set!\n");
}