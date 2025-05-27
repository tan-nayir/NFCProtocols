# NFCProtocols Library

**Supported protocols:**  
- Apple VAS

## Requirements

- mbedTLS 3.x
- C++23

## Usage

```cpp
// Initialize NFCProtocols with transceive and logging callbacks
NFCProtocols::SetCallbacks(
    // Transceive callback
    [this](auto data) -> std::optional<std::vector<std::byte>> {
        auto result = this->tclTransceive(data);
        if (result)
            return *result;
        return std::nullopt;
    },
    // Logging callback
    [](auto format, auto args) { std::vprintf(format, args); }
);

// Define constants for Apple VAS pass reading
const char* PASS_ID = "your.pass.identifier";
// Private key in DER format
const uint8_t PRIVATE_KEY[] = { /* ... */ };

// Attempt to read an Apple VAS pass via pass ID
auto vasResult = NFCProtocols::AppleVAS::ReadPass(
    PASS_ID,
    nullptr,
    std::as_bytes(std::span<const uint8_t>(PRIVATE_KEY))
);

if (vasResult) {
    // Successfully read pass data
    std::string passData(reinterpret_cast<const char*>(vasResult->data()), 
                        vasResult->size());
    std::cout << "Pass data: " << passData << std::endl;
} else {
    std::printf("Failed to read Apple Pass: %d\n", vasResult.error());
}
```
