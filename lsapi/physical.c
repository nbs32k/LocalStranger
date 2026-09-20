#include <lsapi.h>

BOOLEAN
LsWritePhysicalMemory (
    _In_ ULONG64 Destination,
    _In_ ULONG64 Source,
    _In_ ULONG64 Size,
    _In_ ULONG64 PhysicalPml4
    )
{
    ULONG BytesReturned;
    BOOLEAN Result;
    WINNOTIFY_READWRITE_PHYSICAL_MEMORY Request;

    memset(&Request, 0, sizeof(WINNOTIFY_READWRITE_PHYSICAL_MEMORY));
    Request.MustBeNonZero = 1;
    Request.Source = Source;
    Request.Destination = Destination;
    Request.Size = Size;
    Request.PhysicalPml4 = PhysicalPml4;

    Result = DeviceIoControl(
                    LsDriverHandle,
                    WINNOTIFY_IOCTL_WRITE_PHYSICAL_MEMORY,
                    &Request,
                    sizeof(WINNOTIFY_READWRITE_PHYSICAL_MEMORY),
                    &Request,
                    sizeof(WINNOTIFY_READWRITE_PHYSICAL_MEMORY),
                    &BytesReturned,
                    NULL);

    if (Result == FALSE) {
        return NULL;
    }

    return TRUE;
}

BOOLEAN
LsReadPhysicalMemory (
    _In_ ULONG64 Destination,
    _In_ ULONG64 Source,
    _In_ ULONG64 Size,
    _In_ ULONG64 PhysicalPml4
    )
{
    ULONG BytesReturned;
    BOOLEAN Result;
    WINNOTIFY_READWRITE_PHYSICAL_MEMORY Request;

    memset(&Request, 0, sizeof(WINNOTIFY_READWRITE_PHYSICAL_MEMORY));
    Request.MustBeNonZero = 1;
    Request.Source = Source;
    Request.Destination = Destination;
    Request.Size = Size;
    Request.PhysicalPml4 = PhysicalPml4;

    Result = DeviceIoControl(
                    LsDriverHandle,
                    WINNOTIFY_IOCTL_READ_PHYSICAL_MEMORY,
                    &Request,
                    sizeof(WINNOTIFY_READWRITE_PHYSICAL_MEMORY),
                    &Request,
                    sizeof(WINNOTIFY_READWRITE_PHYSICAL_MEMORY),
                    &BytesReturned,
                    NULL);

    if (Result == FALSE) {
        return FALSE;
    }

    return TRUE;
}