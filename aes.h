// Copyright (c) jfyo2 2026. Licensed under the MIT Licence.
// See the LICENCE file for full licence text.


// aes.h
#ifndef AES_H
#define AES_H

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <array>
#include <vector>
#include <string>
#include <random>
#include <cstdint>
#include <stdexcept>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <windows.h>


// In AES the plaintext is split into "states" which are 4x4 matrices of 8-bit integers
using AES_state = std::array<std::array<uint8_t, 4>, 4>;
// and the key is split up into "words" consisting of 4 8-bit integers 
using Word = std::array<uint8_t, 4>;

class AES {
    public:
        static const uint8_t Sbox[256];
        static const uint8_t InvSbox[256];

        static std::vector<uint8_t> hex_to_bytes(const std::string& hex);
        
        static std::vector<Word> keyExpand(std::vector<uint8_t> key, int Nk, int Nr);
        static void subBytes(AES_state &state);
        static void shiftRows(AES_state &state);
        static void mixColumn(AES_state &state);
        static void keyAddition(AES_state &state, std::vector<Word> key, int round);
        static AES_state encryptState(AES_state &state, std::vector<uint8_t> key, int bits);
        static std::string encryptMsg(std::string plaintext, std::string keystr, int bits); // for ease of use will use strings for keys in the full encryption. but for intermediate functions we use the 'raw' datatype that makes most sense for the function.  
        static void InvMixColumn(AES_state &state);
        static void InvShiftRows(AES_state &state);
        static void InvSubBytes(AES_state &state);
        static AES_state decryptState(AES_state &state, std::vector<uint8_t> key, int bits);
        static std::string decryptMsg(std::string ciphertext, std::string keystr, int bits);
};

class B64 {
    public: 
        static std::string base64_encode(const std::vector<uint8_t>& data);
        static std::vector<uint8_t> base64_decode(const std::string& encoded);
};

#endif