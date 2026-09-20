#pragma once

#include <stdint.h>

namespace core::context {

    namespace ntos {
        [[nodiscard]] auto init() -> bool;

        inline uint64_t base_addr = 0;
        inline uint64_t base_user_module = 0;

        inline uint64_t mm_pte_base = 0;

        inline uint64_t nt_add_atom = 0;
    }

    namespace ntdll {
        [[nodiscard]] auto init() -> bool;

        inline uint64_t base_addr = 0;
        inline uint64_t nt_add_atom = 0;
    }
}