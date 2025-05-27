#include <mbedtls/ecp.h>
#include <cstring>
#include "NFCProtocols.hpp"
#include "AppleVASReader.hpp"
#include "pm3_compat.h"
#include "vas.h"

using namespace NFCProtocols;
extern APDUTransceiveCallback g_apduTransceiveCallback;
extern LogFunction g_logFunc;

int AppleVAS::ReadPass(const char *pid, const char *url,
                       std::span<const uint8_t> privateKey,
                       std::span<uint8_t> outBuffer, size_t *numBytesRead)
{
    int pidlen = pid != nullptr ? strlen(pid) : 0;
    int urllen = url != nullptr ? strlen(url) : 0;

    if (outBuffer.size_bytes() < 64)
    {
        PrintAndLogEx(FAILED, "Output buffer too small for message");
        return PM3_EINVARG;
    }

    mbedtls_ecp_keypair privKey;
    mbedtls_ecp_keypair_init(&privKey);
    if (LoadReaderPrivateKey(privateKey.data(), privateKey.size_bytes(),
                             &privKey) != PM3_SUCCESS)
    {
        mbedtls_ecp_keypair_free(&privKey);
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Requesting pass type id... %s", pid);

    uint8_t pidhash[32] = {0};
    sha256hash((uint8_t *)pid, pidlen, pidhash);

    size_t clen = 0;
    uint8_t cryptogram[120] = {0};
    uint32_t timestamp = 0;

    *numBytesRead = 0;
    memset(outBuffer.data(), 0, outBuffer.size_bytes());

    int res = VASReader((pidlen > 0) ? pidhash : NULL, url, urllen, cryptogram,
                        &clen, true);
    if (res == PM3_SUCCESS)
    {
        res = DecryptVASCryptogram(pidhash, cryptogram, clen, &privKey,
                                   outBuffer.data(), numBytesRead, &timestamp);
        if (res == PM3_SUCCESS)
        {
            PrintAndLogEx(SUCCESS, "Timestamp... %d (secs since Jan 1, 2001)", timestamp);
        }
    }

    mbedtls_ecp_keypair_free(&privKey);
    return res;
}
