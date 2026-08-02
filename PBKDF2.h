// Copyright (c) jfyo2 2026. Licensed under the MIT Licence.
// See the LICENCE file for full licence text.


// PBKDF2.h
#ifndef PBKDF2_H
#define PBKDF2_H

#include <cstdint>
#include <vector>
#include <array>
#include <cstring>
#include <string> 
#include <iostream>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <random>
#include <windows.h>


class PBKDF2 {
    public: 
        static std::vector<uint8_t> sha256(std::vector<uint8_t> msg_bytes);

        static std::vector<uint8_t> hmac_sha256(std::vector<uint8_t> key_bytes, std::vector<uint8_t> msg_bytes);

        static std::vector<uint8_t> pbkdf2_hmac_sha256(const std::vector<uint8_t>& password, const std::vector<uint8_t>& salt, uint32_t iterations, size_t dkLen);

        static std::vector<uint8_t> pbkdf2_hmac_sha256(const std::vector<uint8_t>& password, const std::vector<uint8_t>& salt, int iterations, int dkLen);

        static std::vector<uint8_t> generate_salt(int salt_len);

        // Polymorphism for the final function -- if no salt is given, a new salt is generated 
        // both return a string that is of the form salt || hash where || is concatenation 
        static std::string pbkdf2_final(std::string password, int keyBits);
        static std::string pbkdf2_final(std::string password, std::string salt, int keyBits);
};

// Bytes/Hex conversion
class BytesHex {
    public: 
        static std::string bytes_to_hex(const std::vector<uint8_t>& bytes);
        static std::vector<uint8_t> hex_to_bytes(const std::string& hex);
};

#endif 