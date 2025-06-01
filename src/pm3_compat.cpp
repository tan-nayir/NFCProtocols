#include <cmath>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <mbedtls/sha256.h>

#include "pm3_compat.h"
#include "NFCProtocols/NFCProtocols.hpp"
#include "NFCProtocols/Utils.hpp"

using namespace NFCProtocols;
extern APDUTransceiveCallback g_apduTransceiveCallback;
extern LogFunction g_logFunc;

extern "C" void pm3_printf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    g_logFunc(format, args);
    va_end(args);
}

extern "C" int Iso7816Select(Iso7816CommandChannel channel, bool activate_field,
                             bool leave_field_on, uint8_t *aid, size_t aid_len,
                             uint8_t *result, size_t max_result_len,
                             size_t *result_len, uint16_t *sw)
{
    auto apdu = Utils::BuildAPDUFrame(0x00, 0xA4, 0x04, 0x00,
                                      std::as_bytes(std::span<const uint8_t>(aid, aid_len)));
    auto ret = ExchangeAPDU14a(reinterpret_cast<const uint8_t *>(apdu.data()), apdu.size(), activate_field, leave_field_on,
                               result, max_result_len, result_len);

    if (*result_len < 2)
        return 200;
    else
        *result_len -= 2;

    if (sw)
        *sw = (result[*result_len] * 0x0100) + result[*result_len + 1];

    return ret;
}

extern "C" int ExchangeAPDU14a(const uint8_t *datain, size_t datainlen,
                               bool activateField, bool leaveSignalON,
                               uint8_t *dataout, size_t maxdataoutlen,
                               size_t *dataoutlen)
{
    auto res = g_apduTransceiveCallback(std::as_bytes(std::span<const uint8_t>(datain, datainlen)));
    if (!res)
    {
        pm3_printf("ExchangeAPDU14a: APDU transceive callback failed\n");
        return PM3_ECARDEXCHANGE;
    }

    if (res->size() > maxdataoutlen)
    {
        pm3_printf("ExchangeAPDU14a: Response too long (%zu bytes, max %zu bytes)\n",
                   res->size(), maxdataoutlen);
        return PM3_EINVARG;
    }

    std::copy(std::begin(*res), std::end(*res), reinterpret_cast<std::byte *>(dataout));
    *dataoutlen = res->size();

    return PM3_SUCCESS;
}

extern "C" int sha256hash(uint8_t *input, int length, uint8_t *hash)
{
    if (!hash || !input)
        return 1;

    auto res = Utils::SHA256Hash(std::as_bytes(std::span<const uint8_t>(input, length)));
    std::copy(std::begin(res), std::end(res), reinterpret_cast<std::byte *>(hash));

    return PM3_SUCCESS;
}

// Implementation from http://www.secg.org/sec1-v2.pdf#subsubsection.3.6.1
extern "C" int ansi_x963_sha256(uint8_t *sharedSecret, size_t sharedSecretLen,
                                uint8_t *sharedInfo, size_t sharedInfoLen,
                                size_t keyDataLen, uint8_t *keyData)
{
    // sha256 hash has (practically) no max input len, so skipping that step

    if (keyDataLen >= 32 * (pow(2, 32) - 1))
    {
        return 1;
    }

    uint32_t counter = 0x00000001;

    for (int i = 0; i < (keyDataLen / 32); ++i)
    {
        uint8_t *hashMaterial = static_cast<uint8_t *>(
            calloc(4 + sharedSecretLen + sharedInfoLen, sizeof(uint8_t)));
        memcpy(hashMaterial, sharedSecret, sharedSecretLen);
        hashMaterial[sharedSecretLen] = (counter >> 24);
        hashMaterial[sharedSecretLen + 1] = (counter >> 16) & 0xFF;
        hashMaterial[sharedSecretLen + 2] = (counter >> 8) & 0xFF;
        hashMaterial[sharedSecretLen + 3] = counter & 0xFF;
        memcpy(hashMaterial + sharedSecretLen + 4, sharedInfo, sharedInfoLen);

        uint8_t hash[32] = {0};
        sha256hash(hashMaterial, 4 + sharedSecretLen + sharedInfoLen, hash);
        free(hashMaterial);

        memcpy(keyData + (32 * i), hash, 32);

        counter++;
    }

    return 0;
}
