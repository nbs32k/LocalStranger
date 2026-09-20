#include <lsapi.h>

HANDLE LsDriverHandle = INVALID_HANDLE_VALUE;

BOOLEAN
LsInitialize (
    VOID
    )
{
    LsDriverHandle = CreateFileW(
                            L"\\\\.\\WinNotify",
                            GENERIC_READ | GENERIC_WRITE,
                            0,
                            NULL,
                            OPEN_EXISTING,
                            0,
                            NULL);

    if (LsDriverHandle == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
LsUninitialize (
    VOID
    )
{
    CloseHandle(LsDriverHandle);
    return TRUE;
}