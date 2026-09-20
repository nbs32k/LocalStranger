#include <lsapi.h>

#include <stdio.h>

BOOLEAN
LsReadVirtualMemory (
    _In_    ULONG64 Source,
    _Inout_ PWINNOTIFY_READ_VIRTUAL_MEMORY Request
    )
{
    ULONG BytesReturned;
    BOOLEAN Result;

    if (Source == 0 || Request == NULL) {
        return FALSE;
    }

    memset(Request, 0, sizeof(WINNOTIFY_READ_VIRTUAL_MEMORY));
    Request->Source = Source;
    Request->Offset = 0;

    Result = DeviceIoControl(
                    LsDriverHandle,
                    WINNOTIFY_IOCTL_READ_VIRTUAL_MEMORY,
                    Request,
                    sizeof(WINNOTIFY_READ_VIRTUAL_MEMORY),
                    Request,
                    sizeof(WINNOTIFY_READ_VIRTUAL_MEMORY),
                    &BytesReturned,
                    NULL);

    //
    // Due to the weird design of the kernel driver, it
    // will only read 3 * sizeof(__int64) bytes as seen
    // in WINNOTIFY_MODULE_READ_RESPONSE's definition.
    //

    if (!Result) {
        printf("LsReadVirtualMemory for %llx failed: %lx\n", Source, GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
LsWriteVirtualMemory (
    _In_    ULONG64 Destination,
    _Inout_ ULONG64 Source,
    _In_    ULONG64 Size
    )
{
    ULONG BytesReturned;
    BOOLEAN Result;
    WINNOTIFY_WRITE_VIRTUAL_MEMORY Request;

    memset(&Request, 0, sizeof(WINNOTIFY_WRITE_VIRTUAL_MEMORY));
    Request.Destination = Destination;
    Request.Source = Source;
    Request.Size = Size;

    Result = DeviceIoControl(
                    LsDriverHandle,
                    WINNOTIFY_IOCTL_WRITE_VIRTUAL_MEMORY,
                    &Request,
                    sizeof(WINNOTIFY_WRITE_VIRTUAL_MEMORY),
                    NULL,
                    0,
                    &BytesReturned,
                    NULL);

    return Result;
}