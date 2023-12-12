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



; make_syscall(SYSCALL_INDEX, NUM_ARGS, arg1, arg2, arg3...)
; where NUM_ARGS is the number of variable "arg" arguments
; will do
; syscall(arg1, arg2, arg3, arg4, arg5, ...)
; and return RAX from the syscall
make_syscall PROC
    ; push non-volatile registers
    push r12
    push r13
    push r14
    push rbx
    push rbp
    push rsi
    push rdi


    ; DEBUGGING STACK ARGS
    mov rbx, [RSP+78h] ; PAGE_NOACCESS
    mov rbx, [RSP+70h] ; MEM_RESERVE
    mov rbx, [RSP+68h] ; pSize
    mov rbx, [RSP+60h] ; Zero
    mov rbx, r9 ; RB
    mov rbx, r8 ; PROC
    mov rbx, rdx ; COUNT
    mov rbx, rcx ; SYSCALL


    mov r12, rcx    ; r12 = SYSCALL ID
    mov r13, rdx    ; r13 = NUM SYSCALL ARGS
    mov r14, r13
    sub r14, 2      ; r14 = NUM STACK ARGS

    ; check if we need to copy
    ; stack args for syscall
    cmp r14, 2
    jle skip_stackcopy  ; if(r14 > 2) {

    mov rbx, rsp

    mov rcx, r14
    sub rcx, 2          ; rax = r14-2 | num args to copy to the stack

    ; make space in our destimation
    mov rax, r14
    imul rax, rax, 8    ; rax = rcx*2
    sub rsp, rax

    ; TODO: this is very clearly
    ; overwriting something important
    ; because RAX is 10
    ; and RCX is 2
    lea rsi, [rbx + 58h + rax]      ; Source pointer (last arg)
    lea rdi, [rsp]              ; Destimation

    ; do copyS
    std                             ; backwards copying
    rep movsq                       ; copy values
    cld                             ; clear direction

skip_stackcopy:         ; }

    ; shift register arguments backwards by two positions
    mov rcx, r8        ; r8 becomes our new RCX
    mov rdx, r9        ; r9 becomes our new RDX

    ; check if >2 args
    cmp r13, 2
    jle call_syscall

    ; copy arg3 to r8
    mov r8, [rbx+58h]

    ; check if >3 args
    cmp r13, 3
    jle call_syscall

    ; copy arg to r8
    mov r9, [rbx+60h]

call_syscall:
    ; Perform the system call

    ; DEBUG STACK ARGS
    ; mov rbx, rcx
    ; mov rbx, rdx
    ; mov rbx, r8
    ; mov rbx, r9
    mov rbx, [rsp+8h]
    mov rbx, [rsp]

    sub rsp, 20h ; shadow pool
    call syscall_idx

    cmp r14, 2
    jle finish_syscall

    ; Restore shifted stack args
    mov rcx, r14
    sub rcx, 2          ; rax = r14-2 | num args to copy to the stack

    ; make space in our destimation
    mov rbx, rcx
    imul rbx, rbx, 8    ; rax = rcx*2
    add rsp, rbx

finish_syscall:
    ; Restore original value of r12 and other registers
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop r14
    pop r13
    pop r12

    ret
make_syscall ENDP

END