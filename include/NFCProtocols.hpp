#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <functional>
#include <cstdarg>

namespace NFCProtocols
{
    using APDUTransceiveCallback = std::function<void(std::span<const uint8_t>, std::span<uint8_t>, size_t *)>;
    using LogFunction = std::function<void(const char *, va_list)>;

    void SetCallbacks(
        APDUTransceiveCallback transceiveCallback,
        LogFunction logFunc);
};
