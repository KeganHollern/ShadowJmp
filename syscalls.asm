.data

ntSyscall QWORD 0h
fakeStack BYTE 100000h DUP(?)

.code

; call any arbitrary syscall
; pass syscall index in r12d
syscall_idx PROC
    xor rax, rax    ; clear rax
    mov r10, rcx    ; 1st arg goes on r10
    mov eax, r12d   ; syscall index onto eax

    ; store some shit I need to restore later
    mov [rsp+8h], rsi
    mov [rsp+10h], rdi
    mov [rsp+18h], r12
    mov [rsp+20h], r13

    ; replace RSP with some fake buffer
    lea r13, [fakeStack+50000h]
    xchg rsp, r13               ; pivot

    ; copy data from old RSP to fake buffer
    ; TODO: only copy data necessary for syscall?
    lea rcx, [r13+200h]         ; stop copying here (exclusive)
    lea rsi, [r13+28h]          ; copy source
    lea rdi, [rsp+28h]          ; copy destination
copy_loop:
    cmp rsi, rcx                ; compare source addr with high address
    je end_copy                 ; if they equal, stop copying
    movsq                       ; move qword from source to dest
    jmp copy_loop
end_copy:

    ; TODO: set RET address to some ROP chain

do_syscall:
    ; TODO: jmp/ret
    syscall
    xchg rsp, r13               ; restore our old RSP

    ; restore some shit i saved earlier
    mov rsi, [rsp+8h]
    mov rdi, [rsp+10h]
    mov r12, [rsp+18h]
    mov r13, [rsp+20h]

    ret
    ; if ntSyscall is set, we jmp to it
    ; instead of do our own syscall
    ; mov rbx, ntSyscall
    ; test rbx, rbx
    ; jz default_syscall

    ; jmp ntSyscall   ; perform syscall from redirector

    ; default_syscall:
    ; syscall
    ; ret
syscall_idx ENDP

; set target `syscall; ret;` for jmp
set_nt_syscall_addr PROC
    mov ntSyscall, rcx
    ret
set_nt_syscall_addr ENDP



make_syscall PROC
    ; 1. setup fake stack & args
    ; 2. xchg rsp, fake_stack
    ; 3. syscall
    ; 4. xchg rsp, fake_stack
    ; 5. ret

    mov r11, rsp        ; lazily store original RSP at r11

    push rbx
    push rbp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    ; RSP-40h

    mov r13, rdx        ; r13 => number of args for the syscall
    mov rax, rcx        ; rax => syscall index


    ; if 0 args, do syscall immediately
    cmp r13, 1
    jl do_syscall

    mov rcx, r8         ; setup 1st arg

    ; if 1 arg, do syscall
    cmp r13, 2
    jl do_syscall

    mov rdx, r9         ; setup 2nd arg

    ; if 2 arg, do syscall
    cmp r13, 3
    jl do_syscall

    mov r8, [r11+28h]   ; setup 3rd arg

    ; if 3 arg, do syscall
    cmp r13, 4
    jl do_syscall

    mov r9, [r11+30h]   ; setup 4th arg

    cmp r13, 5
    jl do_syscall

    ; adjust the stack for alignment
    test r13, 1
    jz no_alignment_needed
    sub rsp, 8h         ; align stack to 16 bytes
no_alignment_needed:

    ; copy stack args for syscall
    mov r14, r13
    sub r14, 4          ; r14 => number of stack args to push

    add r11, 30h        ; move r11 to stack args start (arg7)
push_stack_arg:

    mov r15, r14        ; r15 => r14 (loop counter)
    shl r15, 3          ; r15 => r14*8h
    add r15, r11        ; r15 => r11 + (r14 * 8h)
    push [r15]          ; push the argument onto the stack

    dec r14             ; loop counter--

    cmp r14, 0          ; check if r14 == 0 -- if yes exit loop and syscall
    jne push_stack_arg  ; push next arg


do_syscall:
    mov r12d, eax       ; setup syscall

    ; shadow pool
    sub rsp, 20h

    ; perform syscall
    call syscall_idx

    ; clean shadowpool
    add rsp, 20h

    ; if < 5 args, no stack cleanup needed
    cmp r13, 5
    jl finish_stack_cleanup

    test r13, 1
    jz no_alignment_cleanup
    add rsp, 8h         ; align stack to 16 bytes
no_alignment_cleanup:
    ; calculate # of bytes pushed to stack
    sub r13, 4
    shl r13, 3
    add rsp, r13

finish_stack_cleanup:
    ; RSP-40h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    pop rbx
    ret
make_syscall ENDP

END
