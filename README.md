# Shadow Jmp

Manual Syscalls for Evasion of EDRs and Anticheats

## About

Manual syscalls with an obfuscated callstack to:
1. Avoid user mode hooks on Windows libraries.
2. Obscure caller from instrumentation callbacks.

_Currently only the RIP is obscured, the remainder of the stack is unmodified._

## Before & After

Without ShadowJmp instrumentation callbacks see:

```
STACK DUMP:
        [22996] stack[0]: 0x00007FF79A22310B syscall_idx                <-- BAD
        [22996] stack[1]: 0x00007FF79A2230E7 create_thread_syscall      <-- BAD
        [22996] stack[2]: 0x00000067E037F5C8 UNKNOWN FUNCTION           <-- BAD
        [22996] stack[3]: 0x00000000001FFFFF UNKNOWN FUNCTION           <-- BAD
```

After ShadowJmp instrumentation callbacks see:

```
STACK DUMP:
        [304] stack[0]: 0x00007FF9E006FB34 NtClearEvent                 <-- GOOD
        [304] stack[1]: 0x00007FF7641A30E7 create_thread_syscall        <-- BAD
        [304] stack[2]: 0x0000000496D8FB98 UNKNOWN FUNCTION             <-- BAD
        [304] stack[3]: 0x00000000001FFFFF UNKNOWN FUNCTION             <-- BAD
```

## TODO

ROP chain building to obscure callstack further down.