#include <mapper/mapper.h>
#include <mapper/pe.h>

#include <fstream>
#include <vector>

[[nodiscard]] auto c_mapper::init() -> bool {

    if (!LsInitialize()) {
        printf("[!] c_mapper::init: failed to initialize lsapi!\n");
        return false;
    }

    if (!core::context::ntos::init()) {
        printf("[!] c_mapper::init: failed to initialize ntos context!\n");
        return false;
    }

    if (!core::context::ntdll::init()) {
        printf("[!] c_mapper::init: failed to initialize ntdll context!\n");
        return false;
    }

    return true;
}

[[nodiscard]] auto c_mapper::uninit() -> bool {

    return LsUninitialize();
}

[[nodiscard]] auto c_mapper::load(uint8_t* file_data, uint32_t file_size, uint8_t pe_flags) -> bool {

    c_pe pe_image(file_data, file_size);

    auto size_of_image = pe_image.get_size_of_image();
    printf("[~] c_mapper::load: driver size of image: 0x%lx\n", size_of_image);

    auto ex_allocate_pool = core::utils::get_kernel_export("ExAllocatePool");
    if (!ex_allocate_pool) {
        printf("[!] c_mapper::load: couldn't find ExAllocatePool address\n");
        return false;
    }
    auto driver_base = this->call_kernel_func<uint64_t>(ex_allocate_pool,
        0, size_of_image
        );
    if (driver_base == 0) {
        printf("[!] c_mapper::load: couldn't allocate memory for the driver\n");
        return false;
    }
    printf("[~] c_mapper::load: driver base allocated at 0x%llx\n", driver_base);

    // @note: allocate vector bytes (so we don't bother with deallocations)
    // and map the image so that it's ready to be copied into target base
    std::vector<uint8_t> mapped_bytes;
    if (!pe_image.map(driver_base, mapped_bytes, pe_flags)) {
        return false;
    }

    // @note: copy the mapping
    if (!LsWriteVirtualMemory(driver_base, reinterpret_cast<ULONG64>(mapped_bytes.data()), mapped_bytes.size())) {
        printf("[!] c_mapper::load: couldn't copy mapping to base address\n");
        return false;
    }

    auto entry_point = driver_base + pe_image.get_entry_point();
    printf("[~] c_mapper::load: driver entry point at 0x%llx\n", entry_point);

    auto status = this->call_kernel_func<NTSTATUS>(entry_point, nullptr, nullptr);
    printf("[~] c_mapper::load: driver entry returned status 0x%lx\n", status);

    printf("[+] c_mapper::load: successfully loaded the driver\n");
    return true;
}

[[nodiscard]] auto c_mapper::load(std::string_view file_path, uint8_t pe_flags) -> bool {

    std::ifstream file(file_path.data(), std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        printf("[!] c_mapper::load: couldn't open file %s\n", file_path.data());
        return false;
    }

    auto size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        printf("[!] c_mapper::load: couldn't read file %s\n", file_path.data());
        return false;
    }

    printf("[+] c_mapper::load: attempting to load file %s\n", file_path.data());
    if (!this->load(buffer.data(), size, pe_flags)) {
        printf("[!] c_mapper::load: operation has failed\n");
        return false;
    }

    return true;
}

auto c_mapper::find_pt_for_va(uint64_t virtual_address) -> uint64_t {

    // @note: recursiveness
    auto mm_pte_base = core::context::ntos::mm_pte_base;

    uint64_t pte_addr = mm_pte_base + ((virtual_address >> 9) & 0x7FFFFFFFF8);
    uint64_t pde_addr = mm_pte_base + ((pte_addr >> 9) & 0x7FFFFFFFF8);
    uint64_t ppe_addr = mm_pte_base + ((pde_addr >> 9) & 0x7FFFFFFFF8);

    // @note: 3-level
    //if (!LsReadVirtualMemory(ppe_addr, &request)) return 0;
    //uint64_t ppe_val = *reinterpret_cast<uint64_t*>(&request.Data[0]);
    //if (!(ppe_val & 1)) return 0;
    //if (ppe_val & (1ULL << 7)) return ppe_addr; // 1gb large page

    // @note: 2-level
    WINNOTIFY_READ_VIRTUAL_MEMORY request{};
    if (!LsReadVirtualMemory(pde_addr, &request)) return 0;
    uint64_t pde_val = *reinterpret_cast<uint64_t*>(&request.Data[0]);
    if (!(pde_val & 1)) return 0;
    if (pde_val & (1ULL << 7)) return pde_addr; // 2mb large page

    // @note: 1-level
    if (!LsReadVirtualMemory(pte_addr, &request)) return 0;
    uint64_t pte_val = *reinterpret_cast<uint64_t*>(&request.Data[0]);
    if (!(pte_val & 1)) return 0;

    return pte_addr; // 4096 bytes page
}