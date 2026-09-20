#include <lsapi.h>

BOOLEAN
LsReadProcessMemory(
    _In_ ULONG64 ProcessId,
    _In_ ULONG64 SourceAddress,
    _In_ ULONG64 TargetAddress,
    _In_ ULONG64 BufferSize
    )
{
    ULONG BytesReturned;
    BOOLEAN Result;
    WINNOTIFY_READ_PROCESS_MEMORY Request;

    memset(&Request, 0, sizeof(WINNOTIFY_READ_PROCESS_MEMORY));
    Request.ProcessId = ProcessId;
    Request.SourceAddress = SourceAddress;
    Request.TargetAddress = TargetAddress;
    Request.BufferSize = BufferSize;

    Result = DeviceIoControl(
        LsDriverHandle,
        WINNOTIFY_IOCTL_READ_PROCESS_MEMORY,
        &Request,
        sizeof(WINNOTIFY_READ_PROCESS_MEMORY),
        &Request,
        sizeof(WINNOTIFY_READ_PROCESS_MEMORY),
        &BytesReturned,
        NULL);

    if (Result == FALSE) {
        return NULL;
    }

    return Result;
}

PPEB
LsGetProcessPeb (
    _In_ ULONG64 ProcessId
    )
{
    ULONG BytesReturned;
    BOOLEAN Result;
    WINNOTIFY_GET_PROCESS_PEB Request;

    memset(&Request, 0, sizeof(WINNOTIFY_GET_PROCESS_PEB));
    Request.ProcessId = ProcessId;

    Result = DeviceIoControl(
                    LsDriverHandle,
                    WINNOTIFY_IOCTL_GET_PROCESS_PEB,
                    &Request,
                    sizeof(WINNOTIFY_GET_PROCESS_PEB),
                    &Request,
                    sizeof(WINNOTIFY_GET_PROCESS_PEB),
                    &BytesReturned,
                    NULL);

    if (Result == FALSE) {
        return NULL;
    }

    return (PPEB)Request.PebAddress;
}

ULONG64
LsGetProcessBase (
    _In_ ULONG64 ProcessId
    )
{
    ULONG BytesReturned;
    BOOLEAN Result;
    WINNOTIFY_GET_PROCESS_BASE Request;

    memset(&Request, 0, sizeof(WINNOTIFY_GET_PROCESS_BASE));
    Request.ProcessId = ProcessId;

    Result = DeviceIoControl(
                    LsDriverHandle,
                    WINNOOTIFY_IOCTL_GET_PROCESS_PML4,
                    &Request,
                    sizeof(WINNOTIFY_GET_PROCESS_BASE),
                    &Request,
                    sizeof(WINNOTIFY_GET_PROCESS_BASE),
                    &BytesReturned,
                    NULL);

    if (Result == FALSE) {
        return NULL;
    }

    return Request.ProcessBase;
}

ULONG64
LsGetProcessPml4 (
    _In_ ULONG64 ProcessId
    )
{
    ULONG BytesReturned;
    BOOLEAN Result;
    WINNOTIFY_GET_PROCESS_PML4 Request;

    memset(&Request, 0, sizeof(WINNOTIFY_GET_PROCESS_PML4));
    Request.ProcessId = ProcessId;
    Request.CheckMinImageSize = FALSE;

    Result = DeviceIoControl(
                    LsDriverHandle,
                    WINNOOTIFY_IOCTL_GET_PROCESS_PML4,
                    &Request,
                    sizeof(WINNOTIFY_GET_PROCESS_PML4),
                    &Request,
                    sizeof(WINNOTIFY_GET_PROCESS_PML4),
                    &BytesReturned,
                    NULL);

    if (Result == FALSE) {
        return NULL;
    }

    return Request.SystemCr3;
}

ULONG64
LsGetKernelPml4 (
    VOID
    )
{
    ULONG BytesReturned;
    BOOLEAN Result;
    WINNOTIFY_GET_KERNEL_PML4 Request;

    memset(&Request, 0, sizeof(WINNOTIFY_GET_KERNEL_PML4));

    Result = DeviceIoControl(
                    LsDriverHandle,
                    WINNOTIFY_IOCTL_GET_KERNEL_PML4,
                    &Request,
                    sizeof(WINNOTIFY_GET_KERNEL_PML4),
                    &Request,
                    sizeof(WINNOTIFY_GET_KERNEL_PML4),
                    &BytesReturned,
                    NULL);

    if (Result == FALSE) {
        return NULL;
    }

    return Request.SystemCr3;
}

ULONG64
LsGetKernelModuleBase (
    _In_ PCHAR ModuleName
    )
{
    ULONG BytesReturned;
    BOOLEAN Result;
    WINNOTIFY_GET_KERNEL_MODULE_BASE Request;

    memset(&Request, 0, sizeof(WINNOTIFY_GET_KERNEL_MODULE_BASE));
    Request.ModuleName = ModuleName;

    Result = DeviceIoControl(
                    LsDriverHandle,
                    WINNOTIFY_IOCTL_GET_KERNEL_MODULE_BASE,
                    &Request,
                    sizeof(WINNOTIFY_GET_KERNEL_MODULE_BASE),
                    &Request,
                    sizeof(WINNOTIFY_GET_KERNEL_MODULE_BASE),
                    &BytesReturned,
                    NULL);

    if (Result == FALSE) {
        return NULL;
    }

    return Request.ModuleBaseAddress;
}