
public set_nt_syscall_addr

.data

ntSyscall QWORD 0h


.code

; call any arbitrary syscall
; pass syscall index in r12d
syscall_idx PROC
    xor rax, rax    ; clear rax
    mov r10, rcx    ; 1st arg goes on r10
    mov eax, r12d   ; syscall index onto eax

    ; if ntSyscall is set, we jmp to it
    ; instead of do our own syscall
    mov rbx, ntSyscall
    test rbx, rbx
    jz default_syscall

    jmp ntSyscall   ; perform syscall from redirector

default_syscall:
    syscall
    ret
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

    ; 1. setup args
    ; 2. syscall
    ; 3. ret

    ; 1. rcx -> rax
    ; 2. rdx -> num_syscall_args
    ; 3. r8 -> r10
    ; 4. r9 -> rdx
    ; 5. rsp+20h -> r8
    ; 6. rsp+28h -> r9
    ; 7. rsp+30h -> pushed (rsp-8h)
    ; 8. rsp+38h -> pushed (rsp-10h)
    ; 9. rsp+40h -> pushed (rsp-18h)

    ; can store values in shadow space
    ; rsp -> rsp+18h

    ; always align to 10h
    ; so if odd # of args, run an extra sub rsp, 8h b4 pushing arguments to stack

    ; rcx - arg1
    ; rdx - arg2
    ; r8  - arg3
    ; r9  - arg4
    ; [rsp+20h] - arg5
    ; this is because the value is from +20h - +28h

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
