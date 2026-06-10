#pragma once
#include <cstdio>
#include <type_traits>

template <typename T>
bool read_at(FILE* file, long offset, T& out)
{
    if (fseek(file, offset, SEEK_SET) != 0)
        return false;

    return fread(&out, sizeof(T), 1, file) == 1;
}
