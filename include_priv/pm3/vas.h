#pragma once
#include <mbedtls/ecp.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C"
{
#endif

    int LoadReaderPrivateKey(const uint8_t *buf, size_t bufLen,
                             mbedtls_ecp_keypair *privKey);

    int DecryptVASCryptogram(uint8_t *pidHash, uint8_t *cryptogram,
                             size_t cryptogramLen,
                             mbedtls_ecp_keypair *privKey, uint8_t *out,
                             size_t *outLen, uint32_t *timestamp);

    int VASReader(uint8_t *pidHash, const char *url, size_t urlLen,
                  uint8_t *cryptogram, size_t *cryptogramLen,
                  bool verbose);

#if defined(__cplusplus)
}
#endif
