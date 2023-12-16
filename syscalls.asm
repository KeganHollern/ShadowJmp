.data

ntSyscall QWORD 0h
ropGadget QWORD 0h

fakeStack BYTE 100000h DUP(?)

.code

; call any arbitrary syscall
; pass syscall index in r12d
syscall_idx PROC
    xor rax, rax                ; clear rax
    mov r10, rcx                ; 1st arg goes on r10
    mov eax, r12d               ; syscall index onto eax

    ; replace RSP with our fake stack buffer
    ; is this sussy?
    lea r13, [fakeStack+99900h]
    xchg rsp, r13               ; pivot

    ; copy data from old RSP to fake buffer
    mov rcx, rbx                ; stop copying here (exclusive)
    lea rsi, [r13+28h]          ; copy source
    lea rdi, [rsp+28h]          ; copy destination
copy_loop:
    cmp rsi, rcx                ; compare source addr with high address
    je end_copy                 ; if they equal, stop copying
    movsq                       ; move qword from source to dest
    jmp copy_loop
end_copy:

do_syscall:
    mov r12, ntSyscall
    test r12, r12
    jz default_syscall          ; JMP not configured- do manual syscall

    mov r12, ropGadget
    test r12, r12
    jz default_syscall          ; ROP not configured- do manual syscall

    mov [rsp], r12              ; install ROP

    jmp ntSyscall               ; JMP into NtDll & ROP restore RSP

default_syscall:
    syscall                     ; do manual syscall
    xchg rsp, r13               ; restore RSP

    ret
syscall_idx ENDP

; this is an example gadget
; in real world we'd make a real
; rop chain to restore rsp
test_rop_gadget PROC
    xchg rsp, r13
    ret
test_rop_gadget ENDP


; set RET target for rop gadget
set_rop_gadget PROC
    mov ropGadget, rcx
    ret
set_rop_gadget ENDP

; set target `syscall; ret;` for jmp
set_nt_syscall_addr PROC
    mov ntSyscall, rcx
    ret
set_nt_syscall_addr ENDP



make_syscall PROC
    mov r11, rsp        ; lazily store original RSP at r11

    push rbx
    push rbp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15

    mov rbx, rsp        ; store RSP - used for stack pivot copying

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

    ; if 4 arg, do syscall
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

     ; store some shit I need to restore later
    mov [rsp], rsi
    mov [rsp+8h], rdi
    mov [rsp+10h], r12
    mov [rsp+18h], r13

    ; perform syscall
    call syscall_idx

    ; restore some shit i saved earlier
    mov rsi, [rsp]
    mov rdi, [rsp+8h]
    mov r12, [rsp+10h]
    mov r13, [rsp+18h]

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
