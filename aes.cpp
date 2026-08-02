// Copyright (c) jfyo2 2026. Licensed under the MIT Licence.
// See the LICENCE file for full licence text.

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


#include "aes.h"
#include "PBKDF2.h"



/* Implementation based loosely on Chapter 4 of the book Understanding Cryptography by Paar, Pelzl*/

// The AES substitution box 
const uint8_t AES::Sbox[256] =
{ /*  0    1    2    3    4    5    6    7    8    9    a    b    c    d    e    f */
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76, /*0*/
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0, /*1*/
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15, /*2*/
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75, /*3*/
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84, /*4*/
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf, /*5*/
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8, /*6*/
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2, /*7*/
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73, /*8*/
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb, /*9*/
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79, /*a*/
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08, /*b*/
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a, /*c*/
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e, /*d*/
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf, /*e*/
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16  /*f*/
};


const uint8_t AES::InvSbox[256] =
{ /*  0    1    2    3    4    5    6    7    8    9    a    b    c    d    e    f  */
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb, /*0*/
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb, /*1*/
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e, /*2*/
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25, /*3*/
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92, /*4*/
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84, /*5*/
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06, /*6*/
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b, /*7*/
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73, /*8*/
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e, /*9*/
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b, /*a*/
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4, /*b*/
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f, /*c*/
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef, /*d*/
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61, /*e*/
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d  /*f*/
};



static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";


/* --- Stuff needed to modify the form of the plaintext --- */

// Plaintext can be converted into bytes (i.e. a std::vector<uint8_t>) via the following easy cast:
//     std::vector<uint8_t> bytes(plaintext.begin(), plaintext.end());
// we don't need a separate function for this, so will just do it when encrypting the text

// We do want functions for converting a string of bytes from a plaintext to an AES_state and vice versa
// This is simple; we just dump them into the columns from top to bottom then left to right 
AES_state bytes_to_state(const std::vector<uint8_t>& block) {
    AES_state state;
    for (int i = 0; i < 16; i++) {
        state[i % 4][i / 4] = block[i];
    }
    return state;
}

std::vector<uint8_t> state_to_bytes(const AES_state& state) {
    std::vector<uint8_t> block(16);
    for (int i = 0; i < 16; i++) {
        block[i] = state[i % 4][i / 4];
    }
    return block;
}

// Finally, since AES_state has 16 entries, we need the plaintext to have a number of bits that is a multiple of 16
// To do this, we pad the end using the PKCS#7 convention: 
std::vector<uint8_t> pkcs7_pad(std::vector<uint8_t> data) {
    size_t pad_len = 16 - (data.size() % 16);
    data.insert(data.end(), pad_len, static_cast<uint8_t>(pad_len));
    return data;
}

std::vector<uint8_t> pkcs7_unpad(std::vector<uint8_t> data) {
    if (data.empty()) return data; 
    uint8_t pad_len = data.back();
    data.resize(data.size() - pad_len);
    return data;
}


// Finally we implement base64 conversion to turn the cipher text (in the form std::vector<uint8_t>) into a string and vice versa 
// standard algorithm, easy to find online 
std::string B64::base64_encode(const std::vector<uint8_t>& data) {
    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);
    int val = 0, bits = 0;

    for (uint8_t byte : data) {
        val = (val << 8) | byte;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            result.push_back(base64_chars[(val >> bits) & 0x3F]);
            val &= (1 << bits) - 1; // Mask out consumed bits to prevent overflow
        }
    }

    // Handle trailing bits (if input size was not a multiple of 3)
    if (bits > 0) {
        result.push_back(base64_chars[(val << (6 - bits)) & 0x3F]);
    }

    // Add padding
    while (result.size() % 4 != 0) {
        result.push_back('=');
    }

    return result;
}


std::vector<uint8_t> B64::base64_decode(const std::string& encoded) {
    // Construct lookup table once
    static const std::vector<int> T = []() {
        std::vector<int> t(256, -1);
        for (int i = 0; i < 64; i++) {
            t[static_cast<unsigned char>(base64_chars[i])] = i;
        }
        return t;
    }();

    std::vector<uint8_t> result;
    result.reserve((encoded.size() * 3) / 4);
    int val = 0, bits = 0;

    for (unsigned char c : encoded) {
        if (T[c] == -1) {
            if (c == '=') break; // Padding reached, stop decoding
            continue;            // Skip non-base64 chars (newlines, spaces, etc.)
        }
        val = (val << 6) | T[c];
        bits += 6;
        while (bits >= 8) {
            bits -= 8;
            result.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
            val &= (1 << bits) - 1; // Mask out consumed bits to prevent overflow
        }
    }

    return result;
}


/* --- Stuff needed for ENCRYPTION --- */

/* The AES encryption algorithm works like this for a single block: We have a state which is a 4x4 matrix of 8 bit integers. We have the following operations:
- Generate key matrix using keyExpansion -- complicated algorithm, see code 
- Apply byte substitution, subBytes, where we swap the state entries 
with corresponding elements of Sbox
- Apply shiftRows -- pushes the ith row left by i spaces (counting starting at 0th row), modulo 4   
- Apply mixColumn -- for each column of the state, we multiply it by the matrix 
02 03 01 01
01 02 03 01
01 01 02 03
03 01 01 02 
where the multiplication is done in the Galois field GF(2^8). There is a smart way to implement this using the so-called 'xtime' algorithm and bitwise XOR, see code. 
- Entrywise XOR the entries of the state with the corresponding entries of the key matrix. This is called the key addition (implemented as keyAddition) layer
These are all done in this order multiple times for several "rounds".
*/

// First we implement the key expansion. First step is to implement the fn g()
// described in the book. 
// here we are using the method given in FIPS-197 (explanation courtesy of Sonnet 5)
// along with https://github.com/sh1r0/pixAES/blob/master/AES.cpp#L121 as a reference
Word subWord(Word &w) {
    return { AES::Sbox[w[0]], AES::Sbox[w[1]], AES::Sbox[w[2]], AES::Sbox[w[3]] }; 
}

Word g(Word &w, uint8_t rc) {
    // first we perform the "rotation" + substitution
    Word rot = { w[1], w[2], w[3], w[0] };
    Word rotsub = subWord(rot); 

    // next we XOR the first byte with rc
    rotsub[0] ^= rc;
    return rotsub;
}

// here Nk represents the key length in words and Nr represents the number of rounds. 
/* AES-128: Nk=4, Nr=10 -> 44 words
AES-192: Nk=6, Nr=12 -> 52 words
AES-256: Nk=8, Nr=14 -> 60 words */
std::vector<Word> AES::keyExpand(std::vector<uint8_t> key, int Nk, int Nr) {
    int Nb = 4;
    std::vector<Word> W(Nb * (Nr + 1));

    // copy the original key into the first Nk words
    for (int i = 0; i < Nk; i++) {
        W[i] = { key[4*i], key[4*i+1], key[4*i+2], key[4*i+3] };
    }

    int RC[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

    for (int i = Nk; i < Nb * (Nr + 1); i++) {
        Word temp = W[i-1];

        // we only apply g to the leftmost bytes
        if (i % Nk == 0) {
            temp = g(temp, RC[i/Nk - 1]);

        // this is the fn h() described in the book. if the key is 256 bits
        // we do an extra substitution 
        } else if (Nk > 6 && i % Nk == 4) {
            temp = subWord(temp);
        }

        // finally XOR each box with the previous 
        for (int b = 0; b < 4; b++) {
            W[i][b] = W[i - Nk][b] ^ temp[b];
        }
    }

    return W;
}



// Byte substitution layer 
void AES::subBytes(AES_state &state) {
    int r, c;
    for (r=0; r<4; r++) {
        for (c=0; c<4; c++) { 
            state[r][c] = AES::Sbox[state[r][c]];
        }
    }
}


// ShiftRows layer 
void AES::shiftRows(AES_state &state) {
    int r, c;
    uint8_t temp[4];

    for (r=0; r<4; r++) {
        for (c=0; c<4; c++)  
            temp[c] = state[r][(c+r) % 4];
        for (c=0; c<4; c++)  
            state[r][c] = temp[c];
    }
}

// We can implement multiplication in the Galois field GF(2^8) efficiently using the xtime algorithm, which is implemented as follows: 
uint8_t xtime(uint8_t a) {
    uint8_t high_bit = a & 0x80;
    uint8_t result = a << 1;
    if (high_bit) {
        result ^= 0x1B; // reduce mod the AES polynomial x^8+x^4+x^3+x+1
    }
    return result;
}

// MixColumn layer 
// with xtime we have a fast algorithm for doing the matrix multiplication
void AES::mixColumn(AES_state &state) {
    for (int c=0; c<4; c++) {
        uint8_t a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];

        state[0][c] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
        state[1][c] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        state[2][c] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        state[3][c] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    }  
}

// Key addition layer (final layer)
void AES::keyAddition(AES_state &state, std::vector<Word> key, int round) {
    for (int c=0; c<4; c++) 
        for (int r=0; r<4; r++)
            state[r][c] ^= key[4*round + c][r];;
}


// Finally we can do the full encryption 
// First: the algorithm for encrypting a single state 
AES_state AES::encryptState(AES_state &state, std::vector<uint8_t> key, int bits) {
    // First determine Nk and Nr from the bits 
    int Nk, Nr;
    if (bits == 128) 
        Nk=4, Nr=10;
    else if (bits == 192)
        Nk=6, Nr=12;
    else if (bits == 256)
        Nk=8, Nr=14;
    else {
        std::cout << "Key bit size not valid.";
        return state;
    }

    // now we do the algorithm
    std::vector<Word> W = keyExpand(key, Nk, Nr);

    keyAddition(state, W, 0);

    for (int round = 1; round < Nr; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumn(state);
        keyAddition(state, W, round);
    }

    subBytes(state);
    shiftRows(state);
    keyAddition(state, W, Nr);

    return state;
}

/* Now we implement AES for a full message, not just a single state.
We use the CBC convention to deal securely with multiple blocks. */ 
std::string AES::encryptMsg(std::string plaintext, std::string keystr, int bits) {
    // convert plaintext, key to bytes
    std::vector<uint8_t> bytes(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> key = BytesHex::hex_to_bytes(keystr);

    // add padding so splits into sequences of length 16 with nothing left over
    bytes = pkcs7_pad(bytes);
    
    // split stream of bytes into AES states 
    std::vector<AES_state> plaintext_states; 
    plaintext_states.reserve(bytes.size() / 16);

    for (int i = 0; i < bytes.size(); i += 16) {
        std::vector<uint8_t> block = std::vector<uint8_t>(bytes.begin() + i, bytes.begin() + i + 16);
        AES_state state = bytes_to_state(block);
        plaintext_states.push_back(state);
    }

    // now we need to do CBC to the states 
    // algorithm goes like this: 
    // - generate an initialization vector (IV)
    // - for states P1,P2,... in plaintext_states, and key K, do 
    // C1 = E(P1 XOR IV), C2 = E(P2 XOR C1), C3 = E(P3 XOR C2), ...
    // where E is the encryptState() function 
    // first step is to generate the random IV
    std::vector<uint8_t> iv(16);
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto& iv_byte : iv) 
        iv_byte = static_cast<uint8_t>(dist(rd));
    
    // Next we XOR the blocks as above with the following: 
    std::vector<AES_state> encrypted_states;
    std::vector<uint8_t> previous = iv;

    // loop through states
    for (AES_state &P_state : plaintext_states) {
        std::vector<uint8_t> P_bytes = state_to_bytes(P_state);
        std::vector<uint8_t> XORed(16);

        // now XOR the bytes together 
        for (int i=0; i<16; i++)
            XORed[i] = P_bytes[i] ^ previous[i];

        AES_state XORed_states = bytes_to_state(XORed);

        // encrypt XORed states and add to vector of encrypted states
        AES_state encryptedstate = encryptState(XORed_states, key, bits);
        encrypted_states.push_back(encryptedstate);
        // update previous
        previous = state_to_bytes(encryptedstate);
    }
    // CBC complete 

    // Final thing is to package all this into a single string output 
    // Setup variables 
    std::vector<uint8_t> encrypted_bits;
    encrypted_bits.reserve(16 + encrypted_states.size() * 16);

    // we prefix the output with the random iv 
    encrypted_bits.insert(encrypted_bits.end(), iv.begin(), iv.end());

    // then after that add the bytes for the AES states one by one 
    for (const auto& state : encrypted_states) {
        auto block = state_to_bytes(state);
        encrypted_bits.insert(encrypted_bits.end(), block.begin(), block.end());
    }

    // finally use the base64 conversion function to turn encrypted_bits into a string 
    return B64::base64_encode(encrypted_bits);
}



/* --- Stuff needed for DECRYPTION --- */
/* The algorithm (for a single AES state) works like this: 
- Invert the keyAddition. Since this is composed of XORs it is self-inverse. 
- Invert mixColumn 
- Invert shiftRows
- Invert subBytes  */ 

/* To invert mixColumn, we multiply in GF(2^8) by the matrix
0E 0B 0D 09
09 0E 0B 0D
0D 09 0E 0B
0B 0D 09 0E 
Unlike in mixColumn itself, the multiplications by 09, 0B, 0D, 0E are complex enough that we can't write them all in one line. However we can once again draw on a known algorithm using xtime. Idea: Using xtime repeatedly gives us multiplication by 2, 4, 8,... :
    mul02(a) = xtime(a)
    mul04(a) = xtime(xtime(a))
    mul08(a) = xtime(xtime(xtime(a)))
Then each target coefficient decomposes as:
    09 = 8 + 1 -> mul09(a) = mul08(a) ^ a
    0B = 8 + 2 + 1 -> mul0B(a) = mul08(a) ^ mul02(a) ^ a
    0D = 8 + 4 + 1 -> mul0D(a) = mul08(a) ^ mul04(a) ^ a
    0E = 8 + 4 + 2 -> mul0E(a) = mul08(a) ^ mul04(a) ^ mul02(a)
We can easily just get an LLM to pull up functions for all of these without manually typing it all out. */
uint8_t mul09(uint8_t a) {
    uint8_t a2 = xtime(a);
    uint8_t a4 = xtime(a2);
    uint8_t a8 = xtime(a4);
    return a8 ^ a;
}
uint8_t mul0B(uint8_t a) {
    uint8_t a2 = xtime(a);
    uint8_t a4 = xtime(a2);
    uint8_t a8 = xtime(a4);
    return a8 ^ a2 ^ a;
}
uint8_t mul0D(uint8_t a) {
    uint8_t a2 = xtime(a);
    uint8_t a4 = xtime(a2);
    uint8_t a8 = xtime(a4);
    return a8 ^ a4 ^ a;
}
uint8_t mul0E(uint8_t a) {
    uint8_t a2 = xtime(a);
    uint8_t a4 = xtime(a2);
    uint8_t a8 = xtime(a4);
    return a8 ^ a4 ^ a2;
}


void AES::InvMixColumn(AES_state &state) {
    for (int c = 0; c < 4; c++) {
        uint8_t a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];

        state[0][c] = mul0E(a0) ^ mul0B(a1) ^ mul0D(a2) ^ mul09(a3);
        state[1][c] = mul09(a0) ^ mul0E(a1) ^ mul0B(a2) ^ mul0D(a3);
        state[2][c] = mul0D(a0) ^ mul09(a1) ^ mul0E(a2) ^ mul0B(a3);
        state[3][c] = mul0B(a0) ^ mul0D(a1) ^ mul09(a2) ^ mul0E(a3);
    }
}


// Inverting shiftRows -- straightforward, copy shiftRows with the shift going the other way 
void AES::InvShiftRows(AES_state &state) {
    int r, c;
    uint8_t temp[4];

    for (r=0; r<4; r++) {
        for (c=0; c<4; c++)  
            temp[c] = state[r][(c - r + 4) % 4]; // the +4 before the %4 is needed because C++'s % can return negative results for negative operands (unlike e.g. Python).
        for (c=0; c<4; c++)  
            state[r][c] = temp[c];
    }
}

// Inverting subBytes 
// Byte substitution layer 
void AES::InvSubBytes(AES_state &state) {
    int r, c;
    for (r=0; r<4; r++) {
        for (c=0; c<4; c++) { 
            state[r][c] = AES::InvSbox[state[r][c]];
        }
    }
}


// Decryption function for a single state 
AES_state AES::decryptState(AES_state &state, std::vector<uint8_t> key, int bits) {
    // First determine Nk and Nr from the bits 
    int Nk, Nr;
    if (bits == 128) 
        Nk=4, Nr=10;
    else if (bits == 192)
        Nk=6, Nr=12;
    else if (bits == 256)
        Nk=8, Nr=14;
    else { 
        std::cout << "Key bit size not valid.";
        return state; 
    }

    // now we do the algorithm
    std::vector<Word> W = keyExpand(key, Nk, Nr);

    // undo final round (no InvMixColumns here)
    keyAddition(state, W, Nr);
    InvShiftRows(state);
    InvSubBytes(state);
 
    // undo main rounds Nr-1 down to 1
    for (int round = Nr - 1; round >= 1; round--) {
        keyAddition(state, W, round);
        InvMixColumn(state);
        InvShiftRows(state);
        InvSubBytes(state);
    }
 
    // undo initial round key addition
    keyAddition(state, W, 0);

    return state;
}


std::string AES::decryptMsg(std::string ciphertext, std::string keystr, int bits) {
    std::vector<uint8_t> key = BytesHex::hex_to_bytes(keystr);
    std::vector<uint8_t> encrypted_bits = B64::base64_decode(ciphertext);

    // extract encrypted AES states and IV from the encrypted bits
    std::vector<uint8_t> iv(16);
    std::copy(encrypted_bits.begin(), encrypted_bits.begin() + 16, iv.begin());

    std::vector<AES_state> encrypted_states;

    for (int i = 16; i < encrypted_bits.size(); i += 16) {
        std::vector<uint8_t> block(16);
        std::copy(encrypted_bits.begin() + i, encrypted_bits.begin() + i + 16, block.begin());
        encrypted_states.push_back(bytes_to_state(block));
    }
    
    // Reverse the CBC 
    // Since XOR is self-inverse, the inverse of CBC is basically just CBC backwards i.e. for encrypted states C1,C2,... we do P1 = D(C1) XOR IV, P2 = D(C2) XOR P1, ... where D is the decryptState function
    std::vector<uint8_t> previous = iv;
    std::vector<AES_state> plaintext_states; 

    for (AES_state &C_state : encrypted_states) {
        std::vector<uint8_t> C_bytes = state_to_bytes(C_state);
        AES_state XORed_states = decryptState(C_state, key, bits);
        std::vector<uint8_t> XORed = state_to_bytes(XORed_states);

        std::vector<uint8_t> P_bytes(16);
        for (int i=0; i<16; i++)
            P_bytes[i] = XORed[i] ^ previous[i];

        plaintext_states.push_back(bytes_to_state(P_bytes));
        previous = C_bytes;
    }
    // CBC reversal complete 

    // now to extract original stream of bytes and convert back into plaintext
    std::vector<uint8_t> bytes;
    bytes.reserve(plaintext_states.size() * 16);

    for (AES_state &state : plaintext_states) {
        std::vector<uint8_t> block = state_to_bytes(state);
        bytes.insert(bytes.end(), block.begin(), block.end());
    }

    // Reverse padding
    bytes = pkcs7_unpad(bytes);

    // convert bytestream to string 
    return std::string(bytes.begin(), bytes.end());
}



/* --- Test script --- */

// // This stuff is needed for full unicode support on Windows
// #ifdef _WIN32
// #define WIN32_LEAN_AND_MEAN
// #include <windows.h>
// #endif

// int main() {
//     #ifdef _WIN32
//     SetConsoleOutputCP(CP_UTF8);
//     SetConsoleCP(CP_UTF8);
//     #endif

//     std::string mode;
//     int bits;
//     std::string text;
//     std::string key;

//     while (true) {
//         std::cout << "\nPress E to encrypt and D to decrypt, or T for test mode: ";
//         cin >> mode;
//         if (mode != "T") {
//             std::cout << "\nEnter the number of bits: ";
//             cin >> bits;
//         }
        

//         if (mode == "E") {
//             std::cin.ignore(); 
//             std::cout << "\nEnter the plaintext for encryption: ";
//             std::getline(std::cin, text);

//             /* FOR DEBUGGING */
//             std::cout << "DEBUG raw bytes: ";
//             for (unsigned char c : text) {
//                 std::cout << std::hex << (int)c << " ";
//             }
//             std::cout << std::dec << "\n";

//             std::cout << "\nEnter the key: ";
//             std::getline(std::cin, key);
//             try {
//                 string ciphertext = AES::encryptMsg(text, key, bits);
//                 std::cout << "\nCiphertext: " << ciphertext << "\n";
//             } 
//             catch (...) {
//                 std::cout << "\nAn error occurred. Check that your key matches the number of bits inputted.";
//             }
//         }

//         else if (mode == "D") {
//             std::cin.ignore(); // FIX: same leftover-newline issue
//             std::cout << "\nEnter the ciphertext for decryption: ";
//             std::getline(std::cin, text);
//             std::cout << "\nEnter the key: ";
//             std::getline(std::cin, key);
//             try {
//                 string plaintext = AES::decryptMsg(text, key, bits);
//                 std::cout << "\nPlaintext: " << plaintext << "\n";
//             } 
//             catch (...) {
//                 std::cout << "\nAn error occurred. Check that your key matches the number of bits inputted.";
//             }
//         }
//         else if (mode == "T") {
//             struct TestVector {
//                 std::string name;
//                 std::string key;
//                 std::string plaintext;
//                 std::string ciphertext;
//                 int bits;
//             };

//             std::vector<TestVector> vectors = {
//             // AES-128
//             { "AES-128 Vector 1 (FIPS-197 C.1)",
//             "2b7e151628aed2a6abf7158809cf4f3c",
//             "3243f6a8885a308d313198a2e0370734",
//             "3925841d02dc09fbdc118597196a0b32",
//             128 },
//             { "AES-128 Vector 2 (SP800-38A F.1.1)",
//             "2b7e151628aed2a6abf7158809cf4f3c",
//             "6bc1bee22e409f96e93d7e117393172a",
//             "3ad77bb40d7a3660a89ecaf32466ef97",
//             128 },
    
//             // AES-192
//             { "AES-192 Vector 1 (FIPS-197 C.2)",
//             "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
//             "6bc1bee22e409f96e93d7e117393172a",
//             "bd334f1d6e45f25ff712a214571fa5cc",
//             192 },
//             { "AES-192 Vector 2 (SP800-38A F.1.3)",
//             "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
//             "ae2d8a571e03ac9c9eb76fac45af8e51",
//             "974104846d0ad3ad7734ecb3ecee4eef",
//             192 },
    
//             // AES-256
//             { "AES-256 Vector 1 (FIPS-197 C.3)",
//             "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
//             "6bc1bee22e409f96e93d7e117393172a",
//             "f3eed1bdb5d2a03c064b5a7e3db181f8",
//             256 },
//             { "AES-256 Vector 2 (SP800-38A F.1.5)",
//             "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
//             "ae2d8a571e03ac9c9eb76fac45af8e51",
//             "591ccb10d410ed26dc5ba74a31362870",
//             256 }
//             };

//             std::cout << " ===== TESTING ENCRYPT/DECRYPT ROUND-TRIP (CBC + padding + base64) =====\n";
//             for (auto &v : vectors) {
//                 std::string original_plaintext_bytes; 
//                 std::vector<uint8_t> pt_bytes = BytesHex::hex_to_bytes(v.plaintext);
//                 std::string plaintext_as_bytes(pt_bytes.begin(), pt_bytes.end());

//                 std::string ciphertext_b64 = AES::encryptMsg(plaintext_as_bytes, v.key, v.bits);
//                 std::string decrypted = AES::decryptMsg(ciphertext_b64, v.key, v.bits);

//                 bool pass = (decrypted == plaintext_as_bytes);
//                 std::cout << "[" << (pass ? "PASS" : "FAIL") << "] " << v.name << " (round-trip)\n";
//             }
//         }

//     }
// }

