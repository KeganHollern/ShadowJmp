#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <DbgHelp.h>

#include "instrumentation.h"
#include "syscalls.h"

int main() {

    // initialize DbgHelp
    SymSetOptions(SYMOPT_UNDNAME);
    SymInitialize(GetCurrentProcess(), NULL, TRUE);

    // init instrumentation callbacks
    init_callbacks();

    printf("+++ START demo_syscall();\n");
    demo_syscall();
    printf("--- END demo_syscall();\n");

    return 0;
}
