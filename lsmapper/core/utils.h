#pragma once

#include <cstdint>
#include <string>

namespace core::utils {

    [[nodiscard]] auto get_kernel_export(std::string_view name, uint64_t ordinal = 0) -> uint64_t;
    [[nodiscard]] auto get_mm_pte_base() -> uint64_t;
}