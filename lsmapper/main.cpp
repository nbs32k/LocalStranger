#include <Windows.h>
#include <stdio.h>

#include <core/context.h>
#include <core/utils.h>

#include <mapper/mapper.h>

#pragma comment(lib, "lsapi.lib")

auto main(int argc, char** argv) -> int {

    auto mapper = c_mapper::get_inst();

    if (argc < 2) {
        printf("[!] main: not enough arguments\n"
               "usage: lsmapper.exe <path_to_file>\n");
        return -1;
    }

    // @note: initialize the mapper
    if (!mapper->init()) {
        return -1;
    }

    // @note: manual map the wanted driver
    if (!mapper->load(argv[1])) {
        goto unload;
    }

unload:
    // @note: unload the mapper
    if (!mapper->uninit()) {
        return -3;
    }
    return 0;
}