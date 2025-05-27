#pragma once
#include <mbedtls/ecp.h>
#include <array>
#include <vector>
#include <span>
#include <cstddef>
#include <memory>

namespace NFCProtocols
{
    namespace Utils
    {
        using raii_mbedtls_ecp_keypair = std::unique_ptr<mbedtls_ecp_keypair, decltype([](mbedtls_ecp_keypair *key)
                                                                                       { mbedtls_ecp_keypair_free(key); })>;

        std::array<std::byte, 32> SHA256Hash(std::span<const std::byte> input);
        std::vector<std::byte> BuildAPDUFrame(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, std::span<const std::byte> data);
    }
}
