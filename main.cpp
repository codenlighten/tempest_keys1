#include <bitcoin/system.hpp>
#include <openssl/evp.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>

using namespace bc;

// Function to hash data using OpenSSL's EVP method
std::string hash_data_with_evp(const std::string& data) {
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    EVP_MD_CTX* mdctx;

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, data.c_str(), data.size());
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < md_len; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)md_value[i];

    return ss.str();
}

// Function to check for existing keys or generate new ones
wallet::ec_private check_or_generate_keys() {
    std::ifstream infile("keys.txt");
    if (infile.good()) {
        std::string line, wifKey;
        std::getline(infile, line); // Read the private key line
        size_t pos = line.find(": ");
        wifKey = line.substr(pos + 2);
        return wallet::ec_private(wifKey);
    }

    // Generate a new private key
    data_chunk seed(16);
    pseudo_random_fill(seed);
    ec_secret secretKey = bitcoin_hash(seed);
    wallet::ec_private privateKey(secretKey, wallet::ec_private::mainnet_p2kh, false);

    // Store keys in a file
    std::ofstream outfile("keys.txt");
    outfile << "Private Key (WIF): " << privateKey.encoded() << std::endl;
    outfile << "Public Key: " << wallet::ec_public(privateKey).encoded() << std::endl;
    outfile.close();

    std::cout << "Keys generated and stored." << std::endl;
    return privateKey;
}

// Function to hash and sign the user data
void hash_and_sign(const wallet::ec_private& privateKey, const std::string& user_data) {
    // Hash the user data
    std::string data_hash = hash_data_with_evp(user_data);

    // Convert hash to the format expected by libbitcoin
    hash_digest libbitcoin_hash;
    decode_base16(libbitcoin_hash, data_hash);

    // Sign the hash with the private key
    ec_signature signature;
    sign(signature, privateKey.secret(), libbitcoin_hash);

    // Output the user data, hash, and signature
    std::cout << "User Data: " << user_data << std::endl;
    std::cout << "Data Hash: " << data_hash << std::endl;
    std::cout << "Signature: " << encode_base16(signature) << std::endl;
}

int main() {
    // Check for existing keys or generate new ones
    wallet::ec_private privateKey = check_or_generate_keys();

    // Prompt user for data
    std::string user_data;
    std::cout << "Enter data to be hashed and signed: ";
    std::getline(std::cin, user_data);

    // Process the user data
    hash_and_sign(privateKey, user_data);

    return 0;
}

