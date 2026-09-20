#include <core/utils.h>
#include <core/context.h>

#include <Windows.h>

#include <lsapi.h>

[[nodiscard]] auto core::utils::get_kernel_export(std::string_view name, uint64_t ordinal) -> uint64_t {

    LPCSTR export_str = ordinal ? reinterpret_cast<LPCSTR>(ordinal) : name.data();
    auto nt_api = GetProcAddress(reinterpret_cast<HMODULE>(core::context::ntos::base_user_module), export_str);
    if (nt_api == nullptr) {
        return 0;
    }
    
    auto nt_base = core::context::ntos::base_addr;
    auto nt_api_rva = (reinterpret_cast<uint64_t>(nt_api) - core::context::ntos::base_user_module);

    return nt_base + nt_api_rva;
}

[[nodiscard]] auto core::utils::get_mm_pte_base() -> uint64_t {

    auto mm_get_virtual_for_physical = core::utils::get_kernel_export("MmGetVirtualForPhysical");
    if (mm_get_virtual_for_physical == 0) {
        return 0;
    }

    // @note: windows relocates page tables at run time (for KASLR)

    auto mov_opcode = mm_get_virtual_for_physical + 32; // mov     rdx, 0FFFFF68000000000h
    auto mm_pte_base = mov_opcode + 2;  //0FFFFF68000000000h

    WINNOTIFY_READ_VIRTUAL_MEMORY request{};
    LsReadVirtualMemory(mm_pte_base, &request);

    return *reinterpret_cast<uint64_t*>(&request.Data);
}
