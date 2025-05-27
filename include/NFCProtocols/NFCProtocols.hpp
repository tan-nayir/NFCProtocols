#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <functional>
#include <cstdarg>
#include <vector>
#include <optional>

namespace NFCProtocols
{
    // The callback takes a span of bytes representing the APDU command and returns an optional span of bytes for the response
    using APDUTransceiveCallback = std::function<std::optional<std::vector<std::byte>>(std::span<const uint8_t>)>;

    // The log function takes a format string and a variable argument list for logging messages
    using LogFunction = std::function<void(const char *, va_list)>;

    void SetCallbacks(
        APDUTransceiveCallback transceiveCallback,
        LogFunction logFunc);
};
