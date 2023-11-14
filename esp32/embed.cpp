#include "mbedtls/sha256.h"
#include "uECC.h"
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

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
    for (int i = 0; i < 32; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)output[i];

    return ss.str();
}

// Function to generate a new ECC private key using micro-ecc
std::vector<uint8_t> generate_private_key() {
    const struct uECC_Curve_t *curve = uECC_secp256r1(); // Use secp256r1 or secp256k1 if available
    std::vector<uint8_t> private_key(uECC_curve_private_key_size(curve));

    if (!uECC_make_key(private_key.data(), nullptr, curve)) {
        // Handle error - key generation failed
        std::cerr << "Failed to generate private key" << std::endl;
        exit(1);
    }

    return private_key;
}

// Function to sign data with ECC
std::vector<uint8_t> sign_data(const std::vector<uint8_t>& private_key, const std::string& data) {
    const struct uECC_Curve_t *curve = uECC_secp256r1(); // Use secp256r1 or secp256k1 if available
    std::vector<uint8_t> signature(uECC_curve_signature_size(curve));

    if (!uECC_sign(private_key.data(), reinterpret_cast<const uint8_t*>(data.c_str()), data.length(), signature.data(), curve)) {
        // Handle error - signing failed
        std::cerr << "Failed to sign data" << std::endl;
        exit(1);
    }

    return signature;
}

int main() {
    // Generate a private key
    std::vector<uint8_t> private_key = generate_private_key();

    // Prompt user for data
    std::string user_data;
    std::cout << "Enter data to be hashed and signed: ";
    std::getline(std::cin, user_data);

    // Hash the user data
    std::string data_hash = hash_data_with_mbedtls(user_data);

    // Sign the hash
    std::vector<uint8_t> signature = sign_data(private_key, data_hash);

    // Output the results
    std::cout << "User Data: " << user_data << std::endl;
    std::cout << "Data Hash: " << data_hash << std::endl;
    std::cout << "Signature: ";
    for (auto byte : signature) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::endl;

    return 0;
}

