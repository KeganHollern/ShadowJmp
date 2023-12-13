# Shadow Jmp

Manual Syscalls for Evasion of EDRs and Anticheats

## About

Manual syscalls with stack pivot to:
1. Avoid user mode hooks on Windows libraries.
2. Obscure caller from instrumentation callbacks.

### JMP - Before & After

Without ShadowJmp instrumentation callbacks see:

```
STACK DUMP:
        [22996] stack[0]: 0x00007FF79A22310B syscall_idx                <-- BAD
        [22996] stack[1]: 0x00007FF79A2230E7 create_thread_syscall      <-- BAD
```

After ShadowJmp instrumentation callbacks see:

```
STACK DUMP:
        [304] stack[0]: 0x00007FF9E006FB34 NtClearEvent                 <-- GOOD
        [304] stack[1]: 0x00007FF7641A30E7 create_thread_syscall        <-- BAD
```

### Pivot - Before & After

TODO

### ShadowJmp - Before & After

TODO

## TODO

1. Swap RSP
2. Setup stack for syscall
3. Setup ROP chain
4. Jump syscall ret
5. ump back to my code (rop)
6. Restore RSP

## Presentation

1. lets do a manual syscall and hide nothing
2. lets try hiding RIP with JMP into NT Syscall;Ret;
3. lets try using a stack pivot to hide RSP and make the syscall ourselves
4. lets combine 2 and 3 and use a ROP Chain to restore everything without crashing on RET in NT