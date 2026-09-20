#pragma once

#include <cstdint>
#include <vector>

enum e_pe_flags : uint8_t {
    none = 0,
    no_headers = (1 << 0),
};

class c_pe {
private:
    uint8_t* m_buffer;
    uint32_t m_size;

    [[nodiscard]] auto is_valid() -> bool;
    [[nodiscard]] auto copy_sections(std::vector<uint8_t>& out_map) -> bool;
    [[nodiscard]] auto resolve_imports(std::vector<uint8_t>& out_map) -> bool;
    [[nodiscard]] auto fix_security_cookie(std::vector<uint8_t>& out_map) -> bool;
    [[nodiscard]] auto apply_relocations(uint64_t new_base, std::vector<uint8_t>& out_map) -> bool;
public:
    c_pe(uint8_t* file_buffer, uint32_t file_size) :
        m_buffer{ file_buffer }, m_size{ file_size } {
    }

    [[nodiscard]] auto get_size_of_image() -> uint32_t;
    [[nodiscard]] auto get_entry_point() -> uint64_t;

    [[nodiscard]] auto map(uint64_t base_addr, std::vector<uint8_t>& out_map, uint8_t flags = 0) -> bool;
};