#include <core/context.h>
#include <core/utils.h>

#include <stdio.h>

#include <lsapi.h>

[[nodiscard]] auto core::context::ntos::init() -> bool {

    core::context::ntos::base_addr = LsGetKernelModuleBase(const_cast<PCHAR>("ntoskrnl.exe"));
    printf("> core::context::ntos::base_addr: 0x%llx\n", core::context::ntos::base_addr);

    // @note: map and resolve the kernel image into user space
    core::context::ntos::base_user_module = reinterpret_cast<uint64_t>(
        LoadLibraryExW(L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES)
        );
    if (core::context::ntos::base_user_module == 0) {
        printf("[!] core::context::ntos::init: base_user_module is null (0x%lx)\n", GetLastError());
        return false;
    }

    core::context::ntos::mm_pte_base = core::utils::get_mm_pte_base();
    if (core::context::ntos::mm_pte_base == 0) {
        printf("[!] core::context::ntos::init: mm_pte_base is null (0x%lx)\n", GetLastError());
        return false;
    }
    printf("> core::context::ntos::mm_pte_base: 0x%llx\n", core::context::ntos::mm_pte_base);

    // @note: get the NtAddAtom kernel export address
    core::context::ntos::nt_add_atom = core::utils::get_kernel_export("NtAddAtom");
    printf("> core::context::ntos::nt_add_atom: 0x%llx\n", core::context::ntos::nt_add_atom);

    return true;
}

[[nodiscard]] auto core::context::ntdll::init() -> bool {

    // @note: get ntdll base address and NtAddAtom syscall stub address
    core::context::ntdll::base_addr = reinterpret_cast<uint64_t>(GetModuleHandleW(L"ntdll.dll"));
    if (core::context::ntdll::base_addr == 0) {
        printf("[!] core::context::ntdll::init: base_addr is null (0x%lx)\n", GetLastError());
        return false;
    }
    printf("> core::context::ntdll::base_addr: 0x%llx\n", core::context::ntdll::base_addr);

    core::context::ntdll::nt_add_atom = reinterpret_cast<uint64_t>(GetProcAddress(
        reinterpret_cast<HMODULE>(core::context::ntdll::base_addr), "NtAddAtom")
        );
    printf("> core::context::ntdll::nt_add_atom: 0x%llx\n", core::context::ntdll::nt_add_atom);

    return true;
}