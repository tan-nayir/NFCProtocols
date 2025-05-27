#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <functional>
#include <cstdarg>
#include "NFCProtocols.hpp"

namespace NFCProtocols::AppleVAS
{
    int ReadPass(const char *pid, const char *url,
                 std::span<const uint8_t> privateKey,
                 std::span<uint8_t> outBuffer, size_t *numBytesRead);
};
