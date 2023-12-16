#include <stdint.h>
#include <Windows.h>
#include <winternl.h>

// --- types and externs
typedef struct syscall_values {
    uint16_t create_thread;
    uint16_t virtual_alloc;
    uint16_t virtual_protect;
    uint16_t virtual_query;
    uint16_t set_windows_hook_ex;
    uint16_t get_user_message;
} syscall_values;
extern syscall_values values;

extern DWORD64 make_syscall(uint32_t syscall_id, uint32_t num_args, ...);

// --- inline syscalls ---
inline NTSTATUS NTAPI NtAllocateVirtualMemory(
        IN HANDLE ProcessHandle,
        IN OUT PVOID *BaseAddress,
        IN ULONG ZeroBits,
        IN OUT PULONG RegionSize,
        IN ULONG AllocationType,
        IN ULONG Protect
) {
    return (NTSTATUS) make_syscall(
            values.virtual_alloc, 6,
            ProcessHandle, BaseAddress, ZeroBits,
            RegionSize, AllocationType, Protect);
}

inline NTSTATUS NTAPI NtCreateThreadEx(
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
        OUT PVOID lpBytesBuffer
) {
    return (NTSTATUS) make_syscall(
            values.create_thread, 11,
            hThread, DesiredAccess, ObjectAttributes,
            ProcessHandle, lpStartAddress, lpParameter,
            Flags, StackZeroBits, SizeOfStackCommit,
            SizeOfStackReserve, lpBytesBuffer);
}

inline HHOOK NTAPI NtUserSetWindowsHookEx(
        HINSTANCE Mod,
        PUNICODE_STRING ModuleName,
        DWORD ThreadId,
        int HookId,
        HOOKPROC HookProc,
        BOOL Ansi
) {
    return (HHOOK) make_syscall(
            values.set_windows_hook_ex, 6,
            Mod, ModuleName, ThreadId,
            HookId, HookProc, Ansi);
}

inline BOOL APIENTRY NtUserGetMessage(
        PMSG pMsg,
        HWND hWnd,
        UINT MsgFilterMin,
        UINT MsgFilterMax
) {
    return (BOOL) make_syscall(
            values.get_user_message, 4,
            pMsg, hWnd, MsgFilterMin,
            MsgFilterMax);
}

inline BOOL NTAPI NtUserTranslateMessage(
        LPMSG lpMsg,
        UINT flags
) {
    return (BOOL) make_syscall(
            values.get_user_message, 2,
            lpMsg, flags);
}

inline LRESULT NTAPI NtUserDispatchMessage(
        PMSG pMsg
) {
    return (LRESULT) make_syscall(
            values.get_user_message, 1,
            pMsg);
}

/* this isn't working right and I need to fix
 *
inline LRESULT NTAPI NtUserCallNextHookEx(
        int Code,
        WPARAM wParam,
        LPARAM lParam,
        BOOL Ansi
) {
    return (LRESULT) make_syscall(
            values.get_user_message, 4,
            Code, wParam, lParam,
            Ansi);
}
 */

// --- demo function
void init_syscalls();
