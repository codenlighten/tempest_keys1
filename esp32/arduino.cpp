#include <Arduino.h>
#include <vector>
#include "mbedtls/sha256.h"
#include <uECC.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

// RNG function using analogRead
static int RNG(uint8_t *dest, unsigned size) {
    while (size) {
        uint8_t val = 0;
        for (unsigned i = 0; i < 8; ++i) {
            int init = analogRead(0); // Change the pin number if needed
            int count = 0;
            while (analogRead(0) == init) {
                ++count;
            }

            if (count == 0) {
                val = (val << 1) | (init & 0x01);
            } else {
                val = (val << 1) | (count & 0x01);
            }
        }
        *dest = val;
        ++dest;
        --size;
    }
    return 1; // Return 1 to indicate success
}

// Function to hash data using mbedtls SHA256
std::string hash_data_with_mbedtls(const std::string& data) {
    unsigned char output[32]; // SHA256 outputs 32 bytes

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0); // 0 for SHA256
    mbedtls_sha256_update_ret(&ctx, reinterpret_cast<const unsigned char*>(data.c_str()), data.size());
    mbedtls_sha256_finish_ret(&ctx, output);
    mbedtls_sha256_free(&ctx);

    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)output[i];
    }

    return ss.str();
}

// Function to generate a new ECC private key using micro-ecc
std::vector<uint8_t> generate_private_key() {
    const struct uECC_Curve_t *curve = uECC_secp256r1(); // Use secp256r1
    std::vector<uint8_t> private_key(uECC_curve_private_key_size(curve));
    std::vector<uint8_t> public_key(uECC_curve_public_key_size(curve));

    if (!uECC_make_key(public_key.data(), private_key.data(), curve)) {
        Serial.println("Failed to generate private key");
        return std::vector<uint8_t>(); // Return an empty vector to indicate failure
    }

    return private_key;
}

// Function to sign data with ECC
std::vector<uint8_t> sign_data(const std::vector<uint8_t>& private_key, const std::string& data) {
    const struct uECC_Curve_t *curve = uECC_secp256r1(); // Use secp256r1
    std::vector<uint8_t> signature(uECC_curve_private_key_size(curve));

    if (!uECC_sign(private_key.data(), reinterpret_cast<const uint8_t*>(data.c_str()), data.length(), signature.data(), curve)) {
        Serial.println("Failed to sign data");
        return std::vector<uint8_t>(); // Return an empty vector to indicate failure
    }

    return signature;
}

void setup() {
    Serial.begin(9600);
    while (!Serial) {
        ; // wait for serial port to connect
    }

    uECC_set_rng(&RNG); // Set the custom RNG for micro-ecc

    // Generate a private key
    std::vector<uint8_t> private_key = generate_private_key();
    if (private_key.empty()) {
        Serial.println("Private key generation failed");
        return;
    }

    // Example data to be hashed and signed
    std::string user_data = "Example data to be hashed and signed";

    // Hash the user data
    std::string data_hash = hash_data_with_mbedtls(user_data);

    // Sign the hash
    std::vector<uint8_t> signature = sign_data(private_key, data_hash);
    if (signature.empty()) {
        Serial.println("Signing failed");
        return;
    }

    // Output the results
    Serial.println((std::string("User Data: ") + user_data).c_str());
    Serial.println((std::string("Data Hash: ") + data_hash).c_str());
    Serial.print("Signature: ");
    for (auto byte : signature) {
        Serial.print(String(byte, HEX));
    }
    Serial.println();
}

void loop() {
    // Your loop code here
}
