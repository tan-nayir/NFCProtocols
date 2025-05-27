#include <mbedtls/ecp.h>
#include <cstring>
#include "NFCProtocols.hpp"
#include "pm3_compat.h"
#include "vas.h"

using namespace NFCProtocols;
APDUTransceiveCallback g_apduTransceiveCallback = nullptr;
LogFunction g_logFunc = nullptr;

void NFCProtocols::SetCallbacks(APDUTransceiveCallback transceiveCallback, LogFunction logFunc)
{
    g_apduTransceiveCallback = transceiveCallback;
    g_logFunc = logFunc;
}
