#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C"
{
#endif

    typedef enum
    {
        CC_CONTACTLESS,
        CC_CONTACT
    } Iso7816CommandChannel;

    int Iso7816Select(Iso7816CommandChannel channel, bool activate_field,
                      bool leave_field_on, uint8_t *aid, size_t aid_len,
                      uint8_t *result, size_t max_result_len, size_t *result_len,
                      uint16_t *sw);

    int ExchangeAPDU14a(const uint8_t *datain, size_t datainlen, bool activateField,
                        bool leaveSignalON, uint8_t *dataout, size_t maxdataoutlen,
                        size_t *dataoutlen);

    int sha256hash(uint8_t *input, int length, uint8_t *hash);

    int ansi_x963_sha256(uint8_t *sharedSecret, size_t sharedSecretLen,
                         uint8_t *sharedInfo, size_t sharedInfoLen,
                         size_t keyDataLen, uint8_t *keyData);

    void pm3_printf(const char *format, ...);

#define PrintAndLogEx(level, format, ...) pm3_printf(format "\n", ##__VA_ARGS__)
#define APDU_RES_LEN 260
#define APDU_AID_LEN 50

// Error codes                          Usages:
// NOTE: Positive values should be reserved for commands in case they need to return multiple statuses and error codes simultaneously.
// Success (no error)
#define PM3_SUCCESS 0

// Undefined error
#define PM3_EUNDEF -1
// Invalid argument(s)                  client:     user input parsing
#define PM3_EINVARG -2
// Operation not supported by device    client/pm3: probably only on pm3 once client becomes universal
#define PM3_EDEVNOTSUPP -3
// Operation timed out                  client:     no response in time from pm3
#define PM3_ETIMEOUT -4
// Operation aborted (by user)          client/pm3: kbd/button pressed
#define PM3_EOPABORTED -5
// Not (yet) implemented                client/pm3: TBD place holder
#define PM3_ENOTIMPL -6
// Error while RF transmission          client/pm3: fail between pm3 & card
#define PM3_ERFTRANS -7
// Input / output error                 pm3:        error in client frame reception
#define PM3_EIO -8
// Buffer overflow                      client/pm3: specified buffer too large for the operation
#define PM3_EOVFLOW -9
// Software error                       client/pm3: e.g. error in parsing some data
#define PM3_ESOFT -10
// Flash error                          client/pm3: error in RDV4 Flash operation
#define PM3_EFLASH -11
// Memory allocation error              client:     error in memory allocation (maybe also for pm3 BigBuff?)
#define PM3_EMALLOC -12
// File error                           client:     error related to file access on host
#define PM3_EFILE -13
// Generic TTY error
#define PM3_ENOTTY -14
// Initialization error                 pm3:        error related to trying to initialize the pm3 / fpga for different operations
#define PM3_EINIT -15
// Expected a different answer error    client/pm3: error when expecting one answer and got another one
#define PM3_EWRONGANSWER -16
// Memory out-of-bounds error           client/pm3: error when a read/write is outside the expected array
#define PM3_EOUTOFBOUND -17
// exchange with card error             client/pm3: error when cant get answer from card or got an incorrect answer
#define PM3_ECARDEXCHANGE -18

// Failed to create APDU,
#define PM3_EAPDU_ENCODEFAIL -19
// APDU responded with a failure code
#define PM3_EAPDU_FAIL -20

// execute pm3 cmd failed               client/pm3: when one of our pm3 cmd tries and fails. opposite from PM3_SUCCESS
#define PM3_EFAILED -21
// partial success                      client/pm3: when trying to dump a tag and fails on some blocks.  Partial dump.
#define PM3_EPARTIAL -22
// tearoff occurred                      client/pm3: when a tearoff hook was called and a tearoff actually happened
#define PM3_ETEAROFF -23

// Got bad CRC                          client/pm3: error in transfer of data,  crc mismatch.
#define PM3_ECRC -24

// STATIC Nonce detect                  pm3:  when collecting nonces for hardnested
#define PM3_ESTATIC_NONCE -25

// No PACS data                         pm3:  when using HID SAM to retried PACS data
#define PM3_ENOPACS -26

// Got wrong length error               pm3: when received wrong length of data
#define PM3_ELENGTH -27

// No key available                     client/pm3: no cryptographic key available.
#define PM3_ENOKEY -28

// Cryptographic error                  client/pm3: cryptographic operation failed
#define PM3_ECRYPTO -29

// No data                              client/pm3: no data available, no host frame available (not really an error)
#define PM3_ENODATA -98
// Quit program                         client:     reserved, order to quit the program
#define PM3_EFATAL -99
// Regular quit
#define PM3_SQUIT -100

// reserved for future protocol change
#define PM3_RESERVED -128

#define PM3_REASON_UNKNOWN -1

#if defined(__cplusplus)
}
#endif
