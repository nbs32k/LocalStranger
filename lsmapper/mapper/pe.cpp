#include <mapper/pe.h>

#include <core/utils.h>

#include <Windows.h>

[[nodiscard]] auto c_pe::is_valid() -> bool {

    PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_buffer);
    PIMAGE_NT_HEADERS64 nt_headers =
        reinterpret_cast<PIMAGE_NT_HEADERS64>(m_buffer + dos_header->e_lfanew);

    if (dos_header->e_magic != 0x5A4D) {
        printf("[!] c_pe::is_valid: dos header is invalid\n");
        return false;
    }

    if (nt_headers->Signature != 0x00004550) {
        printf("[!] c_pe::is_valid: nt header is invalid\n");
        return false;
    }

    if (nt_headers->FileHeader.Machine != 0x8664) {
        printf("[!] c_pe::is_valid: architecture is invalid\n");
        return false;
    }

    if (!(nt_headers->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) {
        printf("[!] c_pe::is_valid: image must be relocatable\n");
        return false;
    }

    return true;
}

[[nodiscard]] auto c_pe::copy_sections(std::vector<uint8_t>& out_map) -> bool {

    PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_buffer);
    PIMAGE_NT_HEADERS64 nt_headers =
        reinterpret_cast<PIMAGE_NT_HEADERS64>(m_buffer + dos_header->e_lfanew);

    auto section_header = IMAGE_FIRST_SECTION(nt_headers);
    for (uint16_t i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i, ++section_header) {
        
        if (section_header->PointerToRawData == 0 || section_header->SizeOfRawData == 0) {
            continue;
        }

        void* destination = out_map.data() + section_header->VirtualAddress;
        const void* source = m_buffer + section_header->PointerToRawData;

        std::memcpy(destination, source, section_header->SizeOfRawData);
    }

    return true;
}

[[nodiscard]] auto c_pe::resolve_imports(std::vector<uint8_t>& out_map) -> bool {

    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(out_map.data());
    auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(out_map.data() + dos_header->e_lfanew);

    auto import_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.VirtualAddress == 0 || import_dir.Size == 0) {
        return true;
    }

    auto import_desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(out_map.data() + import_dir.VirtualAddress);

    while (import_desc->Name != 0) {
        const char* module_name = reinterpret_cast<const char*>(out_map.data() + import_desc->Name);

        auto thunk_data = reinterpret_cast<PIMAGE_THUNK_DATA64>(
            out_map.data() + (import_desc->OriginalFirstThunk ? import_desc->OriginalFirstThunk : import_desc->FirstThunk)
            );
        auto iat_data = reinterpret_cast<PIMAGE_THUNK_DATA64>(out_map.data() + import_desc->FirstThunk);

        while (thunk_data->u1.AddressOfData != 0) {
            uint64_t func_address = 0;

            if (IMAGE_SNAP_BY_ORDINAL64(thunk_data->u1.Ordinal)) {
                auto ordinal = IMAGE_ORDINAL64(thunk_data->u1.Ordinal);
                func_address = core::utils::get_kernel_export("", ordinal);
            }
            else {
                auto import_by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(out_map.data() + thunk_data->u1.AddressOfData);
                func_address = core::utils::get_kernel_export(import_by_name->Name);
            }

            if (!func_address) {
                return false;
            }

            // @note: write the function address
            iat_data->u1.Function = func_address;

            thunk_data++;
            iat_data++;
        }

        import_desc++;
    }

    return true;
}

[[nodiscard]] auto c_pe::apply_relocations(uint64_t new_base, std::vector<uint8_t>& out_map) -> bool {

    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(out_map.data());
    auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(out_map.data() + dos_header->e_lfanew);

    uint64_t old_base = nt_headers->OptionalHeader.ImageBase;
    int64_t delta = static_cast<int64_t>(new_base - old_base);

    if (delta == 0) {
        return true; // breh
    }

    auto reloc_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0) {
        // @note: weird
        return false;
    }

    auto curr_reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(out_map.data() + reloc_dir.VirtualAddress);
    auto reloc_end = reinterpret_cast<uint8_t*>(curr_reloc) + reloc_dir.Size;

    while (curr_reloc->VirtualAddress != 0 && reinterpret_cast<uint8_t*>(curr_reloc) < reloc_end) {
        uint32_t num_entries = (curr_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
        auto entry = reinterpret_cast<uint16_t*>(curr_reloc + 1);

        for (uint32_t i = 0; i < num_entries; ++i) {
            uint16_t type = entry[i] >> 12;
            uint16_t offset = entry[i] & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                uint64_t* patch_address = reinterpret_cast<uint64_t*>(
                    out_map.data() + curr_reloc->VirtualAddress + offset
                    );
                *patch_address += delta;
            }
            else if (type == IMAGE_REL_BASED_HIGHLOW) {
                uint32_t* patch_address = reinterpret_cast<uint32_t*>(
                    out_map.data() + curr_reloc->VirtualAddress + offset
                    );
                *patch_address += static_cast<uint32_t>(delta);
            }
        }

        curr_reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
            reinterpret_cast<uint8_t*>(curr_reloc) + curr_reloc->SizeOfBlock
            );
    }

    return true;
}

[[nodiscard]] auto c_pe::fix_security_cookie(std::vector<uint8_t>& out_map) -> bool {
   
    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(out_map.data());
    auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(out_map.data() + dos_header->e_lfanew);

    auto load_config_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (load_config_dir.VirtualAddress != 0) {
        auto load_config = reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY64>(
            out_map.data() + load_config_dir.VirtualAddress
            );

        if (load_config->SecurityCookie != 0) {
            uint64_t rva_cookie = load_config->SecurityCookie - nt_headers->OptionalHeader.ImageBase;
            auto cookie_ptr = reinterpret_cast<uint64_t*>(out_map.data() + rva_cookie);
            *cookie_ptr = 0x1337beefcafebabeull ^ __rdtsc();
        }
    }

    return true;
}

[[nodiscard]] auto c_pe::get_size_of_image() -> uint32_t {
    if (!is_valid()) return 0;
    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_buffer);
    auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(m_buffer + dos_header->e_lfanew);
    return nt_headers->OptionalHeader.SizeOfImage;
}

[[nodiscard]] auto c_pe::get_entry_point() -> uint64_t {
    if (!is_valid()) return 0;
    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_buffer);
    auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(m_buffer + dos_header->e_lfanew);
    return nt_headers->OptionalHeader.AddressOfEntryPoint;
}

[[nodiscard]] auto c_pe::map(uint64_t base_addr, std::vector<uint8_t>& out_map, uint8_t flags) -> bool {

    if (!is_valid()) {
        printf("[!] c_pe::map: header is invalid\n");
        return false;
    }

    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_buffer);
    auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(m_buffer + dos_header->e_lfanew);

    auto size_of_image = nt_headers->OptionalHeader.SizeOfImage;
    out_map.resize(size_of_image);

    auto size_of_headers = nt_headers->OptionalHeader.SizeOfHeaders;
    if (size_of_headers > size_of_image) {
        printf("[!] c_pe::map: pe header is invalid\n");
        out_map.clear();
        return false;
    }

    // @note: copy pe headers
    std::memcpy(out_map.data(), m_buffer, size_of_headers);

    if (!this->copy_sections(out_map)) {
        printf("[!] c_pe::map: couldn't copy sections!\n");
        out_map.clear();
        return false;
    }

    if (!this->resolve_imports(out_map)) {
        printf("[!] c_pe::map: couldn't resolve imports!\n");
        out_map.clear();
        return false;
    }

    if (!this->fix_security_cookie(out_map)) {
        printf("[!] c_pe::map: couldn't fix security cookie!\n");
        out_map.clear();
        return false;
    }

    if (!this->apply_relocations(base_addr, out_map)) {
        printf("[!] c_pe::map: couldn't apply relocations!\n");
        out_map.clear();
        return false;
    }

    // @note: erase headers
    if (!(flags & e_pe_flags::no_headers)) {
        std::memset(out_map.data(), 0, size_of_headers);
    }

    return true;
}
