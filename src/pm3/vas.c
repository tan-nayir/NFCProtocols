//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// An implementation of the Value Added Service protocol
//-----------------------------------------------------------------------------

#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "pm3_compat.h"
#include "pm3/tlv.h"
#include "pm3/vas.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/gcm.h"
#include "ecc_point_compression.h"

static int dummy_rng(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    if (buf && len > 0)
        memset(buf, 0x42, len);
    return 0;
}

static uint8_t aid[] = { 0x4f, 0x53, 0x45, 0x2e, 0x56, 0x41, 0x53, 0x2e, 0x30, 0x31 };
static uint8_t getVasUrlOnlyP2 = 0x00;
static uint8_t getVasFullReqP2 = 0x01;

static int ParseSelectVASResponse(const uint8_t *response, size_t resLen, bool verbose) {
    struct tlvdb *tlvRoot = tlvdb_parse_multi(response, resLen);

    const struct tlvdb *versionTlv = tlvdb_find_full(tlvRoot, 0x9F21);
    if (versionTlv == NULL) {
        tlvdb_free(tlvRoot);
        return PM3_ECARDEXCHANGE;
    }
    const struct tlv *version = tlvdb_get_tlv(versionTlv);
    if (version->len != 2) {
        tlvdb_free(tlvRoot);
        return PM3_ECARDEXCHANGE;
    }
    if (verbose) {
        PrintAndLogEx(INFO, "Mobile VAS application version: %d.%d", version->value[0], version->value[1]);
    }
    if (version->value[0] != 0x01 || version->value[1] != 0x00) {
        tlvdb_free(tlvRoot);
        return PM3_ECARDEXCHANGE;
    }

    const struct tlvdb *capabilitiesTlv = tlvdb_find_full(tlvRoot, 0x9F23);
    if (capabilitiesTlv == NULL) {
        tlvdb_free(tlvRoot);
        return PM3_ECARDEXCHANGE;
    }
    const struct tlv *capabilities = tlvdb_get_tlv(capabilitiesTlv);
    if (capabilities->len != 4
            || capabilities->value[0] != 0x00
            || capabilities->value[1] != 0x00
            || capabilities->value[2] != 0x00
            || (capabilities->value[3] & 8) == 0) {
        tlvdb_free(tlvRoot);
        return PM3_ECARDEXCHANGE;
    }

    tlvdb_free(tlvRoot);
    return PM3_SUCCESS;
}

static int CreateGetVASDataCommand(const uint8_t *pidHash, const char *url, size_t urlLen, uint8_t *out, int *outLen) {
    if (pidHash == NULL && url == NULL) {
        PrintAndLogEx(FAILED, "Must provide a Pass Type ID or a URL");
        return PM3_EINVARG;
    }

    if (url != NULL && urlLen > 256) {
        PrintAndLogEx(FAILED, "URL must be less than 256 characters");
        return PM3_EINVARG;
    }

    uint8_t p2 = pidHash == NULL ? getVasUrlOnlyP2 : getVasFullReqP2;

    size_t reqTlvLen = 19 + (pidHash != NULL ? 35 : 0) + (url != NULL ? 3 + urlLen : 0);
    uint8_t *reqTlv = calloc(reqTlvLen, sizeof(uint8_t));
    if (reqTlv == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    uint8_t version[] = {0x9F, 0x22, 0x02, 0x01, 0x00};
    memcpy(reqTlv, version, sizeof(version));

    uint8_t unknown[] = {0x9F, 0x28, 0x04, 0x00, 0x00, 0x00, 0x00};
    memcpy(reqTlv + sizeof(version), unknown, sizeof(unknown));

    uint8_t terminalCapabilities[] = {0x9F, 0x26, 0x04, 0x00, 0x00, 0x00, 0x02};
    memcpy(reqTlv + sizeof(version) + sizeof(unknown), terminalCapabilities, sizeof(terminalCapabilities));

    if (pidHash != NULL) {
        size_t offset = sizeof(version) + sizeof(unknown) + sizeof(terminalCapabilities);
        reqTlv[offset] = 0x9F;
        reqTlv[offset + 1] = 0x25;
        reqTlv[offset + 2] = 32;
        memcpy(reqTlv + offset + 3, pidHash, 32);
    }

    if (url != NULL) {
        size_t offset = sizeof(version) + sizeof(unknown) + sizeof(terminalCapabilities) + (pidHash != NULL ? 35 : 0);
        reqTlv[offset] = 0x9F;
        reqTlv[offset + 1] = 0x29;
        reqTlv[offset + 2] = urlLen;
        memcpy(reqTlv + offset + 3, url, urlLen);
    }

    out[0] = 0x80;
    out[1] = 0xCA;
    out[2] = 0x01;
    out[3] = p2;
    out[4] = reqTlvLen;
    memcpy(out + 5, reqTlv, reqTlvLen);
    out[5 + reqTlvLen] = 0x00;

    *outLen = 6 + reqTlvLen;

    free(reqTlv);
    return PM3_SUCCESS;
}

static int ParseGetVASDataResponse(const uint8_t *res, size_t resLen, uint8_t *cryptogram, size_t *cryptogramLen) {
    struct tlvdb *tlvRoot = tlvdb_parse_multi(res, resLen);

    const struct tlvdb *cryptogramTlvdb = tlvdb_find_full(tlvRoot, 0x9F27);
    if (cryptogramTlvdb == NULL) {
        tlvdb_free(tlvRoot);
        return PM3_ECARDEXCHANGE;
    }
    const struct tlv *cryptogramTlv = tlvdb_get_tlv(cryptogramTlvdb);

    memcpy(cryptogram, cryptogramTlv->value, cryptogramTlv->len);
    *cryptogramLen = cryptogramTlv->len;

    tlvdb_free(tlvRoot);
    return PM3_SUCCESS;
}

int LoadReaderPrivateKey(const uint8_t *buf, size_t bufLen, mbedtls_ecp_keypair *privKey) {
    struct tlvdb *derRoot = tlvdb_parse_multi(buf, bufLen);

    const struct tlvdb *privkeyTlvdb = tlvdb_find_full(derRoot, 0x04);
    if (privkeyTlvdb == NULL) {
        tlvdb_free(derRoot);
        return PM3_EINVARG;
    }
    const struct tlv *privkeyTlv = tlvdb_get_tlv(privkeyTlvdb);

    if (mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, privKey, privkeyTlv->value, privkeyTlv->len)) {
        tlvdb_free(derRoot);
        PrintAndLogEx(FAILED, "Unable to parse private key file. Should be DER encoded ASN1");
        return PM3_EINVARG;
    }

    const struct tlvdb *pubkeyCoordsTlvdb = tlvdb_find_full(derRoot, 0x03);
    if (pubkeyCoordsTlvdb == NULL) {
        tlvdb_free(derRoot);
        PrintAndLogEx(FAILED, "Private key file should include public key component");
        return PM3_EINVARG;
    }
    const struct tlv *pubkeyCoordsTlv = tlvdb_get_tlv(pubkeyCoordsTlvdb);
    if (pubkeyCoordsTlv->len != 66 || pubkeyCoordsTlv->value[0] != 0x00 || pubkeyCoordsTlv->value[1] != 0x04) {
        tlvdb_free(derRoot);
        PrintAndLogEx(FAILED, "Invalid public key data");
        return PM3_EINVARG;
    }

    if (mbedtls_ecp_point_read_binary(&privKey->grp, &privKey->Q, pubkeyCoordsTlv->value + 1, 65)) {
        PrintAndLogEx(FAILED, "Failed to read in public key coordinates");
        tlvdb_free(derRoot);
        return PM3_EINVARG;
    }

    if (mbedtls_ecp_check_pubkey(&privKey->grp, &privKey->Q)) {
        PrintAndLogEx(FAILED, "VAS protocol requires an elliptic key on the P-256 curve");
        tlvdb_free(derRoot);
        return PM3_EINVARG;
    }

    tlvdb_free(derRoot);
    return PM3_SUCCESS;
}

static int GetPrivateKeyHint(mbedtls_ecp_keypair *privKey, uint8_t *keyHint) {
    uint8_t xcoord[32] = {0};
    if (mbedtls_mpi_write_binary(&privKey->Q.X, xcoord, sizeof(xcoord))) {
        return PM3_EINVARG;
    }

    uint8_t hash[32] = {0};
    sha256hash(xcoord, 32, hash);

    memcpy(keyHint, hash, 4);
    return PM3_SUCCESS;
}

static int LoadMobileEphemeralKey(const uint8_t *xcoordBuf, mbedtls_ecp_keypair *pubKey) {
    uint8_t compressedEcKey[33] = {0};
    compressedEcKey[0] = 0x02;
    memcpy(compressedEcKey + 1, xcoordBuf, 32);

    uint8_t decompressedEcKey[65] = {0};
    size_t decompressedEcKeyLen = 0;
    if (mbedtls_ecp_decompress(&pubKey->grp, compressedEcKey, sizeof(compressedEcKey), decompressedEcKey, &decompressedEcKeyLen, sizeof(decompressedEcKey))) {
        return PM3_EINVARG;
    }

    if (mbedtls_ecp_point_read_binary(&pubKey->grp, &pubKey->Q, decompressedEcKey, decompressedEcKeyLen)) {
        return PM3_EINVARG;
    }

    return PM3_SUCCESS;
}

static int internalVasDecrypt(uint8_t *cipherText, size_t cipherTextLen, uint8_t *sharedSecret,
                              uint8_t *ansiSharedInfo, size_t ansiSharedInfoLen,
                              const uint8_t *gcmAad, size_t gcmAadLen, uint8_t *out, size_t *outLen) {
    uint8_t key[32] = {0};
    if (ansi_x963_sha256(sharedSecret, 32, ansiSharedInfo, ansiSharedInfoLen, sizeof(key), key)) {
        PrintAndLogEx(FAILED, "ANSI X9.63 key derivation failed");
        return PM3_EINVARG;
    }

    uint8_t iv[16] = {0};

    mbedtls_gcm_context gcmCtx;
    mbedtls_gcm_init(&gcmCtx);
    if (mbedtls_gcm_setkey(&gcmCtx, MBEDTLS_CIPHER_ID_AES, key, sizeof(key) * 8)) {
        PrintAndLogEx(FAILED, "Unable to use key in GCM context");
        return PM3_EINVARG;
    }

    if (mbedtls_gcm_auth_decrypt(&gcmCtx, cipherTextLen - 16, iv, sizeof(iv), gcmAad, gcmAadLen, cipherText + cipherTextLen - 16, 16, cipherText, out)) {
        PrintAndLogEx(FAILED, "Failed to perform GCM decryption");
        return PM3_EINVARG;
    }

    mbedtls_gcm_free(&gcmCtx);

    *outLen = cipherTextLen - 16;

    return PM3_SUCCESS;
}

int DecryptVASCryptogram(uint8_t *pidHash, uint8_t *cryptogram, size_t cryptogramLen, mbedtls_ecp_keypair *privKey, uint8_t *out, size_t *outLen, uint32_t *timestamp) {
    uint8_t keyHint[4] = {0};
    if (GetPrivateKeyHint(privKey, keyHint) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Unable to generate key hint");
        return PM3_EINVARG;
    }

    if (memcmp(keyHint, cryptogram, 4) != 0) {
        PrintAndLogEx(FAILED, "Private key does not match cryptogram");
        return PM3_EINVARG;
    }

    mbedtls_ecp_keypair mobilePubKey;
    mbedtls_ecp_keypair_init(&mobilePubKey);
    mobilePubKey.grp = privKey->grp;

    if (LoadMobileEphemeralKey(cryptogram + 4, &mobilePubKey) != PM3_SUCCESS) {
        mbedtls_ecp_keypair_free(&mobilePubKey);
        PrintAndLogEx(FAILED, "Unable to parse mobile ephemeral key from cryptogram");
        return PM3_EINVARG;
    }

    mbedtls_mpi sharedSecret;
    mbedtls_mpi_init(&sharedSecret);

    if (mbedtls_ecdh_compute_shared(&privKey->grp, &sharedSecret, &mobilePubKey.Q, &privKey->d, dummy_rng, NULL)) {
        mbedtls_mpi_free(&sharedSecret);
        mbedtls_ecp_keypair_free(&mobilePubKey);
        PrintAndLogEx(FAILED, "Failed to generate ECDH shared secret");
        return PM3_EINVARG;
    }
    mbedtls_ecp_keypair_free(&mobilePubKey);

    uint8_t sharedSecretBytes[32] = {0};
    if (mbedtls_mpi_write_binary(&sharedSecret, sharedSecretBytes, sizeof(sharedSecretBytes))) {
        mbedtls_mpi_free(&sharedSecret);
        PrintAndLogEx(FAILED, "Failed to generate ECDH shared secret");
        return PM3_EINVARG;
    }
    mbedtls_mpi_free(&sharedSecret);

    uint8_t string1[27] = "ApplePay encrypted VAS data";
    uint8_t string2[13] = "id-aes256-GCM";

    uint8_t method1SharedInfo[73] = {0};
    method1SharedInfo[0] = 13;
    memcpy(method1SharedInfo + 1, string2, sizeof(string2));
    memcpy(method1SharedInfo + 1 + sizeof(string2), string1, sizeof(string1));
    memcpy(method1SharedInfo + 1 + sizeof(string2) + sizeof(string1), pidHash, 32);

    uint8_t decryptedData[68] = {0};
    size_t decryptedDataLen = 0;
    if (internalVasDecrypt(cryptogram + 4 + 32, cryptogramLen - 4 - 32, sharedSecretBytes, method1SharedInfo, sizeof(method1SharedInfo), NULL, 0, decryptedData, &decryptedDataLen)) {
        if (internalVasDecrypt(cryptogram + 4 + 32, cryptogramLen - 4 - 32, sharedSecretBytes, string1, sizeof(string1), pidHash, 32, decryptedData, &decryptedDataLen)) {
            return PM3_EINVARG;
        }
    }

    memcpy(out, decryptedData + 4, decryptedDataLen - 4);
    *outLen = decryptedDataLen - 4;

    *timestamp = 0;
    for (int i = 0; i < 4; ++i) {
        *timestamp = (*timestamp << 8) | decryptedData[i];
    }

    return PM3_SUCCESS;
}

int VASReader(uint8_t *pidHash, const char *url, size_t urlLen, uint8_t *cryptogram, size_t *cryptogramLen, bool verbose) {
    uint16_t status = 0;
    size_t resLen = 0;
    uint8_t selectResponse[APDU_RES_LEN] = {0};
    Iso7816Select(CC_CONTACTLESS, false, true, aid, sizeof(aid), selectResponse, APDU_RES_LEN, &resLen, &status);

    if (status != 0x9000) {
        PrintAndLogEx(FAILED, "Card doesn't support VAS");
        return PM3_ECARDEXCHANGE;
    }

    if (ParseSelectVASResponse(selectResponse, resLen, verbose) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Card doesn't support VAS");
        return PM3_ECARDEXCHANGE;
    }

    uint8_t getVasApdu[APDU_RES_LEN];
    int getVasApduLen = 0;

    int s = CreateGetVASDataCommand(pidHash, url, urlLen, getVasApdu, &getVasApduLen);
    if (s != PM3_SUCCESS) {
        return s;
    }

    uint8_t apduRes[APDU_RES_LEN] = {0};
    size_t apduResLen = 0;

    s = ExchangeAPDU14a(getVasApdu, getVasApduLen, false, false, apduRes, APDU_RES_LEN, &apduResLen);
    if (s != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Failed to send APDU");
        return s;
    }

    if (apduResLen == 2 && apduRes[0] == 0x62 && apduRes[1] == 0x87) {
        PrintAndLogEx(WARNING, "Device returned error on GET VAS DATA. Either doesn't have pass with matching id, or requires user authentication.");
        return PM3_ECARDEXCHANGE;
    }

    if (apduResLen == 0 || apduRes[0] != 0x70) {
        PrintAndLogEx(FAILED, "Invalid response from peer");
    }

    return ParseGetVASDataResponse(apduRes, apduResLen, cryptogram, cryptogramLen);
}
