PUBLIC create_thread_syscall
PUBLIC virtual_alloc_syscall
PUBLIC virtual_protect_syscall
PUBLIC virtual_query_syscall

public set_nt_syscall_addr

.data

ntSyscall QWORD 0h


.code

virtual_query_syscall PROC
    ; ecx - Syscall ID
    ; rdx - pAddress
    ; r8 - pBuffer
    ; r9 - length
    ; rsp+28h - pResultLength

    ; store 5th argument in rbx for later use
    mov rbx, qword ptr [rsp+28h]

    ; put syscallid on our syscall_idx id register
    push r12
    xor r12, r12
    mov r12d, ecx

    ; setup arguments
    push rbx                                    ; - pResultLength (6th argument)
    push r9                                     ; - dwLength (5th argument)

    mov r9, r8                                  ; - pBuffer (4th argument)
    xor r8, r8                                  ; - dwInfoClass (3rd argument)
    ; mov rdx, rdx                              ; - lpAddress (2nd argument)
    or rcx, 0FFFFFFFFFFFFFFFFh                  ; - qwProcess (1st argument)

    ; shadow pool
    push r9
    push r8
    push rdx
    push rcx

    ; make syscall
    call syscall_idx

    ; clean stack and return
    add rsp, 30h
    pop r12
    ret
virtual_query_syscall ENDP

virtual_protect_syscall PROC
    ; ecx - Syscall ID
    ; rdx - ppAddress
    ; r8 - length
    ; r9d - dwNewProtect
    ; rsp+28h - pOldProect

    ; collect our 5th argument into rbx
    mov rbx, qword ptr [rsp+28h]

    ; put syscallid on our syscall_idx id register
    push r12
    xor r12, r12
    mov r12d, ecx

    ; store values on stack & get their pointer
    push r8
    lea r10, qword ptr [rsp]
    push rdx
    lea r11, qword ptr [rsp]

    ; setup syscall arguments
    push rbx                                    ; - lpflOldProtect (5th argument)

    or rcx, 0FFFFFFFFFFFFFFFFh                  ; - qwProcess (1st argument)
    mov rdx, r11                                ; - pBaseAddress (2nd argument)
    mov r8, r10                                 ; - pLength (3th argument)
    ; mov r9, r9                                ; - flNewProtect (4th argument)

    ; shadow pool
    push r9
    push r8
    push rdx
    push rcx

    ; make syscall
    call syscall_idx

    ; Cleanup stack and return
    add rsp, 38h
    pop r12
    ret
virtual_protect_syscall ENDP

virtual_alloc_syscall PROC
    ; ecx - Syscall ID
    ; rdx - lppAddress
    ; r8 - length
    ; r9d - dwAllocationType
    ; rsp+28h - dwProtect

    ; collect our 5th arg into rbx
    xor rbx, rbx
    mov ebx, dword ptr [rsp+28h] ; 28 because shadow pool + rbp pushed before call ?

    ; put syscallid on our syscall_idx id register
    push r12
    xor r12, r12
    mov r12d, ecx

    ; store r8 on the stack & get a pointer to its value
    push r8
    lea r10, [rsp]

    ; setup syscall arguments
    push rbx                        ; - dwProect (6th argument)
    push r9                        ; - dwAllocationType (5th argument)

    or rcx, 0FFFFFFFFFFFFFFFFh      ; - qwProcess (1st argument)
    ; mov rdx, rdx                  ; - pBaseAddress (2nd argument)
    xor r8, r8                      ; - dwZeroBits (3rd argument)
    mov r9, r10                     ; - pRegionSize (4th argument)

    ; shadow pool
    push r9
    push r8
    push rdx
    push rcx

    ; make syscall
    call syscall_idx

    ; Cleanup stack and return
    add rsp, 38h
    pop r12
    ret

virtual_alloc_syscall ENDP


create_thread_syscall PROC
    ; ecx - Syscall ID
    ; rdx - Entrypoint
    ; r8  - Argument
    ; r9  - hThread pointer

    ; put syscall id on our syscall_idx id register
    push r12
    xor r12, r12
    mov r12d, ecx

    ; setup arguments for syscall
    push 0h                         ; - lpBytesBuffer (11th argument)
    push 0h                         ; - SizeOfStackReserve (10th argument)
    push 0h                         ; - SizeOfStackCommit (9th argument)
    push 0h                         ; - StackZeroBits (8th argument)
    push 0h                         ; - Flags (7th argument)
    push r8                         ; - lpParameter (6th argument)
    push rdx                        ; - lpStartAddress (5th argument)

    mov rcx, r9                     ; rcx - hThread pointer (1st argument)
    xor rdx, rdx
    mov edx, 1FFFFFh                ; rdx - DesiredAccess (2nd argument)
    xor r8, r8                      ; r8 - ObjectAttributes (3rd argument)
    or r9, 0FFFFFFFFFFFFFFFFh       ; r9 - ProcessHandle (4th argument)

    ; shadow pool
    push r9
    push r8
    push rdx
    push rcx

    ; make syscall
    call syscall_idx

    ; Cleanup stack and return
    add rsp, 58h
    pop r12 ; restore r12
    ret
create_thread_syscall ENDP


; call any arbitrary syscall
; pass syscall index in r12d
syscall_idx PROC
    xor rax, rax
    mov r10, rcx
    mov eax, r12d

    ; ntsyscall is a `syscall; ret;` in ntdll .code segment
    ; if(ntSyscall) { jmp ntSyscall; }
    ; else { syscall; }
    mov rbx, ntSyscall
    test rbx, rbx
    jz default_syscall
    jmp ntSyscall
default_syscall:
    syscall
    ret
syscall_idx ENDP

set_nt_syscall_addr PROC
    ; ntsyscall is a `syscall; ret;` in ntdll .code segment
    mov ntSyscall, rcx
    ret
set_nt_syscall_addr ENDP

END