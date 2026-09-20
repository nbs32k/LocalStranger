#pragma once

//
// Windows header
//

#include <Windows.h>
#include <winternl.h>

//
// Structural definition
//

#pragma pack(push, 1)

#define WINNOTIFY_IOCTL_READ_PROCESS_MEMORY     0x222060
typedef struct _WINNOTIFY_READ_PROCESS_MEMORY {
    ULONG64 ProcessId;
    ULONG64 SourceAddress;
    ULONG64 TargetAddress;
    SIZE_T BufferSize;
} WINNOTIFY_READ_PROCESS_MEMORY, *PWINNOTIFY_READ_PROCESS_MEMORY;

#define WINNOTIFY_IOCTL_CHANGE_PROCESS_MEMORY_PROTECTION 0x22205C
typedef struct _WINNOTIFY_CHANGE_PROCESS_MEMORY_PROTECTION {
    ULONG64 ProcessId;
    PVOID BaseAddress;
    SIZE_T NumberOfBytesToProtect;
    ULONG NewAccessProtection;
    ULONG OldAccessProtection;
} WINNOTIFY_CHANGE_PROCESS_MEMORY_PROTECTION, *PWINNOTIFY_CHANGE_PROCESS_MEMORY_PROTECTION;

#define WINNOTIFY_IOCTL_ALLOCATE_PROCESS_MEMORY 0x222058
typedef struct _WINNOTIFY_ALLOCATE_PROCESS_MEMORY {
    ULONG64 ProcessId;          // IN
    ULONG64 BaseAddress;        // IN OUT
    SIZE_T RegionSize;          // IN OUT
    ULONG AllocationType;       // IN
    ULONG Protect;              // IN
} WINNOTIFY_ALLOCATE_PROCESS_MEMORY, *PWINNOTIFY_ALLOCATE_PROCESS_MEMORY;

#define WINNOTIFY_IOCTL_GET_PROCESS_PEB         0x22204C
typedef struct _WINNOTIFY_GET_PROCESS_PEB {
    ULONG64 ProcessId;  // IN
    ULONG64 PebAddress; // OUT
} WINNOTIFY_GET_PROCESS_PEB, *PWINNOTIFY_GET_PROCESS_PEB;

#define WINNOTIFY_IOCTL_GET_PROCESS_BASE        0x222048
typedef struct _WINNOTIFY_GET_PROCESS_BASE {
    ULONG64 ProcessId;   // IN
    ULONG64 ProcessBase; // OUT
} WINNOTIFY_GET_PROCESS_BASE, *PWINNOTIFY_GET_PROCESS_BASE;

#define WINNOTIFY_IOCTL_WRITE_VIRTUAL_MEMORY    0x222044
typedef struct _WINNOTIFY_WRITE_VIRTUAL_MEMORY {
    ULONG64 Source;
    ULONG64 Size;
    ULONG64 Destination;
} WINNOTIFY_WRITE_VIRTUAL_MEMORY, *PWINNOTIFY_WRITE_VIRTUAL_MEMORY;

#define WINNOTIFY_IOCTL_READ_VIRTUAL_MEMORY     0x222040
typedef struct _WINNOTIFY_READ_VIRTUAL_MEMORY {
    ULONG64 Source;     // IN
    ULONG64 Offset;     // IN
    UCHAR Data[24];     // OUT
    UCHAR Unused[16];
} WINNOTIFY_READ_VIRTUAL_MEMORY, *PWINNOTIFY_READ_VIRTUAL_MEMORY;

#define WINNOOTIFY_IOCTL_GET_PROCESS_PML4       0x222014
typedef struct _WINNOTIFY_GET_PROCESS_PML4 {
    ULONG ProcessId;  // IN
    ULONG Padding;
    ULONG64 SystemCr3;  // OUT
    BOOLEAN CheckMinImageSize; // INOPT
    UCHAR Unused[7];
} WINNOTIFY_GET_PROCESS_PML4, *PWINNOTIFY_GET_PROCESS_PML4;

#define WINNOTIFY_IOCTL_GET_KERNEL_PML4         0x222010
typedef struct _WINNOTIFY_GET_KERNEL_PML4 {
    ULONG64 SystemCr3; // OUT
} WINNOTIFY_GET_KERNEL_PML4, *PWINNOTIFY_GET_KERNEL_PML4;

#define WINNOTIFY_IOCTL_GET_KERNEL_MODULE_BASE  0x22200C
typedef struct _WINNOTIFY_GET_KERNEL_MODULE_BASE {
    PCHAR ModuleName;           // IN
    UCHAR Unused[8];
    ULONG64 ModuleBaseAddress;  // OUT
} WINNOTIFY_GET_KERNEL_MODULE_BASE, * PWINNOTIFY_GET_KERNEL_MODULE_BASE;

#define WINNOTIFY_IOCTL_WRITE_PHYSICAL_MEMORY   0x222004
#define WINNOTIFY_IOCTL_READ_PHYSICAL_MEMORY    0x222000
typedef struct _WINNOTIFY_READWRITE_PHYSICAL_MEMORY {
    ULONG MustBeNonZero;
    ULONG Padding;
    ULONG64 Source;
    ULONG64 Destination;
    ULONG64 Size;
    ULONG64 PhysicalPml4;
} WINNOTIFY_READWRITE_PHYSICAL_MEMORY, * PWINNOTIFY_READWRITE_PHYSICAL_MEMORY;
#pragma pack(pop)

//
// API Set
//

#ifdef LSAPI_IMPL
EXTERN_C HANDLE LsDriverHandle;
#endif

EXTERN_C
BOOLEAN
LsInitialize (
    VOID
    );

EXTERN_C
BOOLEAN
LsUninitialize (
    VOID
    );

//
// Subroutines
//

//
// Kernel and user-mode processes
//

BOOLEAN
LsReadProcessMemory(
    _In_ ULONG64 ProcessId,
    _In_ ULONG64 SourceAddress,
    _In_ ULONG64 TargetAddress,
    _In_ ULONG64 BufferSize
    );

EXTERN_C
ULONG64
LsGetProcessPml4 (
    _In_ ULONG64 ProcessId
    );

EXTERN_C
ULONG64
LsGetKernelPml4(
    VOID
    );

EXTERN_C
ULONG64
LsGetKernelModuleBase (
    _In_ PCHAR ModuleName
    );

//
// Virtual Mm
//

EXTERN_C
BOOLEAN
LsReadVirtualMemory (
    _In_    ULONG64 Source,
    _Inout_ PWINNOTIFY_READ_VIRTUAL_MEMORY Request
    );

EXTERN_C
BOOLEAN
LsWriteVirtualMemory (
    _In_    ULONG64 Destination,
    _Inout_ ULONG64 Source,
    _In_    ULONG64 Size
    );

//
// Physical Mm
//

EXTERN_C
BOOLEAN
LsWritePhysicalMemory (
    _In_ ULONG64 Destination,
    _In_ ULONG64 Source,
    _In_ ULONG64 Size,
    _In_ ULONG64 PhysicalPml4
    );

EXTERN_C
BOOLEAN
LsReadPhysicalMemory(
    _In_ ULONG64 Destination,
    _In_ ULONG64 Source,
    _In_ ULONG64 Size,
    _In_ ULONG64 PhysicalPml4
    );