#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <functional>
#include <cstdarg>
#include <expected>
#include <vector>
#include "NFCProtocols.hpp"

namespace NFCProtocols
{
    namespace AppleVAS
    {
        enum class ErrorCode
        {
            READ_ERROR,
            DECRYPTION_ERROR,
            INVALID_KEY,
            INVALID_ARGUMENT
        };

        std::expected<std::vector<std::byte>, ErrorCode> ReadPass(const char *pid, const char *url,
                                                                  std::span<const std::byte> privateKey);
    }
}
