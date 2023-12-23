# Shadow Jmp

Manual System Calls for Evasion of EDRs and Anticheats

## Goals

1. Avoid user mode hooks on Windows libraries.
2. Obscure caller from instrumentation callbacks.

> See: https://winternl.com/detecting-manual-syscalls-from-user-mode/

## Technique

1. Avoid inline hooks by executing `syscall` by hand.
2. Avoid instrumentation callback RIP checks by JMPing into NtDll to perform the syscall.
    ```asm
        syscall;
        ret;
    ```
3. Avoid instrumentation callbacks RSP checks by [pivoting](https://ir0nstone.gitbook.io/notes/types/stack/stack-pivoting) before executing the syscall.
    ```asm
    xchg r13, rsp;
    ```

Combining these three techniques requires a [ROP chain](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/rop-chaining-return-oriented-programming) to restore the stack after pivoting.

### Hiding RIP

Without ShadowJmp instrumentation callbacks see:

```
STACK DUMP:
        [19344] stack[0]: 0x00007FF74A98586D syscall_idx                <--- BAD
        [19344] stack[1]: 0x00007FF74A9858F1 make_syscall               <--- BAD
```

After ShadowJmp instrumentation callbacks see:

```
STACK DUMP:
        [30920] stack[0]: 0x00007FF9E006FB34 NtClearEvent               <--- GOOD
        [30920] stack[1]: 0x00007FF7DF3D58F1 make_syscall               <--- BAD
```

### Hiding RSP

Without ShadowJmp instrumentation callbacks see:

```
STACK DUMP:
        [19344] stack[0]: 0x00007FF74A98586D syscall_idx                <--- BAD
        [19344] stack[1]: 0x00007FF74A9858F1 make_syscall               <--- BAD
```

After ShadowJmp instrumentation callbacks see:

```
STACK DUMP:
        [41868] stack[0]: 0x00007FF7F325361E syscall_idx                <--- BAD
```

### Hiding both RSP and RIP


Without ShadowJmp instrumentation callbacks see:

```
STACK DUMP:
        [41868] stack[0]: 0x00007FF7F325361E syscall_idx                <--- BAD
```

After ShadowJmp instrumentation callbacks see:

```
STACK DUMP:
        [41348] stack[0]: 0x00007FF9E006FB34 NtClearEvent               <--- GOOD
        [41348] stack[1]: 0x00007FF70AAA1262 ILT+605(test_rop_gadget)   <--- GOOD
```

## TODO Presentation

1. lets do a manual syscall and hide nothing
2. lets try hiding RIP with JMP into NT Syscall;Ret;
3. lets try using a stack pivot to hide RSP and make the syscall ourselves
4. lets combine 2 and 3 and use a ROP Chain to restore everything without crashing on RET in NT