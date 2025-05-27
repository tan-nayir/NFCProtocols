#include "NFCProtocols/Utils.hpp"
#include <mbedtls/sha256.h>

std::array<std::byte, 32> NFCProtocols::Utils::SHA256Hash(std::span<const std::byte> input)
{
    std::array<std::byte, 32> hash = {};

    mbedtls_sha256_context sctx;
    mbedtls_sha256_init(&sctx);
    mbedtls_sha256_starts(&sctx, 0);
    mbedtls_sha256_update(&sctx, reinterpret_cast<const unsigned char *>(input.data()), input.size_bytes());
    mbedtls_sha256_finish(&sctx, reinterpret_cast<unsigned char *>(hash.data()));
    mbedtls_sha256_free(&sctx);

    return hash;
}

std::vector<std::byte> NFCProtocols::Utils::BuildAPDUFrame(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, std::span<const std::byte> data)
{
    std::vector<std::byte> frame;
    frame.reserve(data.size() + 5);

    frame.push_back(static_cast<std::byte>(cla));
    frame.push_back(static_cast<std::byte>(ins));
    frame.push_back(static_cast<std::byte>(p1));
    frame.push_back(static_cast<std::byte>(p2));
    frame.push_back(static_cast<std::byte>(data.size()));
    frame.insert(frame.end(), data.begin(), data.end());

    return frame;
}
