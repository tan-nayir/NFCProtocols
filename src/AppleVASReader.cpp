#include <mbedtls/ecp.h>
#include <cstring>

#include "NFCProtocols/Utils.hpp"
#include "NFCProtocols/NFCProtocols.hpp"
#include "NFCProtocols/AppleVASReader.hpp"
#include "pm3_compat.h"
#include "pm3/vas.h"

using namespace NFCProtocols;
using namespace AppleVAS;
using namespace Utils;

extern APDUTransceiveCallback g_apduTransceiveCallback;
extern LogFunction g_logFunc;

std::expected<std::vector<std::byte>, ErrorCode> NFCProtocols::AppleVAS::ReadPass(const char *pid, const char *url, std::span<const std::byte> privateKey)
{
    std::vector<std::byte> outBuffer(64);
    size_t numBytesRead = 0;
    size_t clen = 0;
    uint8_t cryptogram[120] = {0};
    uint32_t timestamp = 0;

    int pidlen = pid != nullptr ? strlen(pid) : 0;
    int urllen = url != nullptr ? strlen(url) : 0;

    auto privKey = raii_mbedtls_ecp_keypair{new mbedtls_ecp_keypair};
    mbedtls_ecp_keypair_init(privKey.get());
    if (LoadReaderPrivateKey(reinterpret_cast<const uint8_t *>(privateKey.data()), privateKey.size_bytes(),
                             privKey.get()) != PM3_SUCCESS)
        return std::unexpected(ErrorCode::INVALID_KEY);

    auto pidhash = Utils::SHA256Hash(std::as_bytes(std::span<const char>(pid, pidlen)));

    PrintAndLogEx(INFO, "Requesting pass id... %s", pid);
    if (VASReader((pidlen > 0) ? reinterpret_cast<uint8_t *>(pidhash.data()) : NULL, url, urllen, cryptogram,
                  &clen, true) != PM3_SUCCESS)
    {
        PrintAndLogEx(FAILED, "Failed to read pass");
        return std::unexpected(ErrorCode::READ_ERROR);
    }

    if (DecryptVASCryptogram(reinterpret_cast<uint8_t *>(pidhash.data()), cryptogram, clen, privKey.get(),
                             reinterpret_cast<uint8_t *>(outBuffer.data()), &numBytesRead, &timestamp) != PM3_SUCCESS)
    {
        PrintAndLogEx(FAILED, "Failed to decrypt pass");
        return std::unexpected(ErrorCode::DECRYPTION_ERROR);
    }

    PrintAndLogEx(SUCCESS, "Timestamp... %d (secs since Jan 1, 2001)", timestamp);
    outBuffer.resize(numBytesRead);
    return outBuffer;
}
