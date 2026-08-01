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


#include "PBKDF2.h"


// standard algorithm for converting bytes to hex
std::string BytesHex::bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

// standard algorithm for converting hex to bytes 
std::vector<uint8_t> BytesHex::hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("BytesHex::hex_to_bytes: hex string must have even length");
    }
 
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
 
    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        bytes.push_back(byte);
    }
 
    return bytes;
}

/* PBKDF2 is a hashing algorithm recommended by NIST. There are more secure methods (e.g. argon2id) but PBKDF2 is still very secure and crucially, fairly simple to implement. 
The algorithm consists of two basic tools:
- Hash it using SHA-256
- Apply the HMAC algorithm to it to create two separate padded keys 
PBKDF2 stretches and hashes a password into a derived key of any length, using HMAC-SHA-256 repeatedly. 
*/

/* --- SHA-256 --- */
// We use these constants K_i and H_i: 
const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

// we also need the following "right rotation" algorithm
// this is equivalent to calculating (x / 2^n) BITWISE-OR (x /* 2^(32-n)) 
uint32_t rrot(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}


/* PBKDF2::sha256(std::vector<uint8_t> msg_bytes);
Algorithm goes like this: 
- Input: a string "msg"
- Pad the string: append a single 1 bit, append 0 bits until length is 56 mod 64
- Append the original message length, in bits, as a 64-bit big-endian integer
For each resulting 64-byte block: 
- Split into 16 32-bit words w
- Run the following algorithm (pseudocode): 
- extend to 64 words as follows: 
   for i in 16..63:
       s0 = rightrotate(w[i-15], 7) xor rightrotate(w[i-15], 18) xor (w[i-15] >> 3)
       s1 = rightrotate(w[i-2], 17) xor rightrotate(w[i-2], 19) xor (w[i-2] >> 10)
       w[i] = w[i-16] + s0 + w[i-7] + s1   (mod 2^32)
    Initialize  a=H[0], b=H[1], c=H[2], d=H[3], e=H[4], f=H[5], g=H[6], h=H[7]
    for i in 0..63:
       S1 = rightrotate(e,6) xor rightrotate(e,11) xor rightrotate(e,25)
       ch = (e and f) xor ((not e) and g)
       temp1 = h + S1 + ch + K[i] + w[i]
       S0 = rightrotate(a,2) xor rightrotate(a,13) xor rightrotate(a,22)
       maj = (a and b) xor (a and c) xor (b and c)
       temp2 = S0 + maj

       h = g
       g = f
       f = e
       e = d + temp1
       d = c
       c = b
       b = a
       a = temp1 + temp2
- Set H[0] += a, H[1] += b, ..., H[7] += h (mod 2^32) 
- After all blocks, concatenate H[0..7] big-endian 
*/
std::vector<uint8_t> PBKDF2::sha256(std::vector<uint8_t> msg_bytes) {
    // fresh initialize H on each call
    uint32_t H[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };

    uint64_t msg_length_in_bits = (uint64_t)msg_bytes.size() * 8;

    // pad 0x80 
    msg_bytes.push_back(0x80);
    // pad 0x00 until 56 mod 64
    while (msg_bytes.size() % 64 != 56) 
        msg_bytes.push_back(0x00);
    // pad big endian original msg length in bits
    for (int i=7; i>=0; i--)
        msg_bytes.push_back((uint8_t)(msg_length_in_bits >> (i*8)));


    // Next: for each 64-byte block, we split into 16 different 32-bit words, big-endian 
    for (size_t block = 0; block < msg_bytes.size(); block += 64) {
        uint32_t w[64];
        for (int i=0; i<16; i++) {
            w[i] = (msg_bytes[block+i*4] << 24) | (msg_bytes[block+i*4+1] << 16) | (msg_bytes[block+i*4+2] << 8) | (msg_bytes[block+i*4+3]);
        }

        // then run the extension algorithm:
        for (int i=16; i<64; i++) {
            uint32_t s0 = rrot(w[i-15],7) ^ rrot(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = rrot(w[i-2],17) ^ rrot(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }

        uint32_t a=H[0], b=H[1], c=H[2], d=H[3], e=H[4], f=H[5], g=H[6], h=H[7];

        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rrot(e,6) ^ rrot(e,11) ^ rrot(e,25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + SHA256_K[i] + w[i];
            uint32_t S0 = rrot(a,2) ^ rrot(a,13) ^ rrot(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h=g; g=f; f=e; e=d + temp1;
            d=c; c=b; b=a; a=temp1 + temp2;
        }

        H[0] += a; H[1] += b; H[2] += c; H[3] += d;
        H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }

    // Finally: big-endian concatenation 
    std::vector<uint8_t> digest(32);
    for (int i = 0; i < 8; i++) {
        digest[i*4]   = (uint8_t)(H[i] >> 24);
        digest[i*4+1] = (uint8_t)(H[i] >> 16);
        digest[i*4+2] = (uint8_t)(H[i] >> 8);
        digest[i*4+3] = (uint8_t)(H[i]);
    }
    return digest;
}

/* std::vector<uint8_t> PBKDF2::hmac_sha256(std::vector<uint8_t> key_bytes, std::vector<uint8_t> msg_bytes);
Next we implement HMAC-SHA256. This combines a key and a message using two nested hash calls. The algorithm goes as follows: 
- If key is longer than 64 bytes, hash it first: key = sha256(key)
- Pad key with zero bytes up to 64 bytes 
- Build two padded keys by XORing with fixed constants:
    opad = key XOR (0x5c repeated 64 times)
    ipad = key XOR (0x36 repeated 64 times)
- Result: sha256(opad || sha256(ipad || message)), where || means concatenation. */

std::vector<uint8_t> PBKDF2::hmac_sha256(std::vector<uint8_t> key_bytes, std::vector<uint8_t> msg_bytes) { 
    if (key_bytes.size() > 64) {
        auto digest = sha256(key_bytes);
        key_bytes = std::vector<uint8_t>(digest.begin(), digest.end());
    } 

    // pad up to 64 bytes -- can do using the resize() operator
    key_bytes.resize(64, 0x00);

    std::vector<uint8_t> opad(64);
    std::vector<uint8_t> ipad(64);

    // build two padded keys: 
    for (int i=0; i<64; i++) {
        opad[i] = key_bytes[i] ^ 0x5c;
        ipad[i] = key_bytes[i] ^ 0x36;
    }

    // construct sha256(opad || sha256(ipad || message)) where || is concatenation 
    std::vector<uint8_t> temp = ipad;
    temp.insert(temp.end(), msg_bytes.begin(), msg_bytes.end());
    std::vector<uint8_t> temp2 = sha256(temp);

    std::vector<uint8_t> outer_input = opad;
    outer_input.insert(outer_input.end(), temp2.begin(), temp2.end());
    return sha256(outer_input);
}

/* PBKDF2::pbkdf2_hmac_sha256(const std::vector<uint8_t>& password, const std::vector<uint8_t>& salt, size_t iterations, size_t dkLen);
Finally we implement full PBKDF2. Algorithm is as follows: 
Inputs: password, salt, iteration count c, desired output length dkLen. Note that for generating a key of bits B in AES (where B \in {128, 192, 256}) we put dkLen = B/8.
Define an empty vector derived_key. Initialize i=1. 
While derived_key has length in bytes < dkLen:
    - Base case: let U_1(i) = hmac_sha256(password, salt || INT_32_BE(i)), where INT_32_BE(i) is i as a 4-byte big-endian integer (we will call salt || INT_32_BE(i) "salt_and_index") and T_1(i) = U_1(i)
    - For j=2,3,...,c, compute U_j(i) = hmac_sha256(password, U_{j-1}(i)) and T_j(i) = U_1(i) xor U_2(i) xor ... xor U_j(i)
    - This results in a value T_c(i). Attach this to the end of derived_key.
Once dkLen bytes are met/exceeded, truncate any additional bytes so the exact length is dkLen. */
std::vector<uint8_t> PBKDF2::pbkdf2_hmac_sha256(const std::vector<uint8_t>& password, const std::vector<uint8_t>& salt, int iterations, int dkLen) {
    std::vector<uint8_t> derived_key;
    uint32_t i = 1;
    
    while (derived_key.size() < dkLen) {
        // create salt_and_index 
        std::vector<uint8_t> salt_and_index = salt;
        salt_and_index.push_back((uint8_t)(i >> 24));
        salt_and_index.push_back((uint8_t)(i >> 16));
        salt_and_index.push_back((uint8_t)(i >> 8));
        salt_and_index.push_back((uint8_t)(i));

        std::vector<uint8_t> current_U_j = PBKDF2::hmac_sha256(password, salt_and_index);
        std::vector<uint8_t> current_T_j = current_U_j; // set T_1 = U_1

        for (int j=2; j<=iterations; j++) {
            current_U_j = PBKDF2::hmac_sha256(password, current_U_j);

            // define T_j (i) as T_{j-1} (i) xor U_j (i)
            // the xor is done bitwise so we need to loop over all bits
            for (size_t k = 0; k < current_T_j.size(); k++) 
                current_T_j[k] ^= current_U_j[k];
        }
        // attach T_c (i) to the end of 
        derived_key.insert(derived_key.end(), current_T_j.begin(), current_T_j.end());
        i++;
    }

    // final resize
    derived_key.resize(dkLen);
    return derived_key;
}

// Salt generation function
std::vector<uint8_t> PBKDF2::generate_salt(int salt_len) {
    std::vector<uint8_t> salt(salt_len);
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto& byte : salt) {
        byte = static_cast<uint8_t>(dist(rd));
    }
    return salt;
}

/* std::string pbkdf2_final(std::string password, int keyBits);
Version of pbkdf2_final with automatic generation of salt. Takes in a password and a number of keyBits, and converts it to a hex string of that many keyBits that can be used as an AES key. */
std::string PBKDF2::pbkdf2_final(std::string password, int keyBits) {
    // Validate keyBits matches your AES key sizes before doing any work
    if (keyBits != 128 && keyBits != 192 && keyBits != 256) {
        throw std::invalid_argument("keyBits must be 128, 192, or 256");
    }

    int salt_len = 16; // 16 bytes is a standard salt size 
    int dkLen = keyBits / 8;
    int iterations = 100000; // selected after some testing  
    // Generate the salt 
    std::vector<uint8_t> salt = PBKDF2::generate_salt(salt_len);

    // Cast password to bytes 
    std::vector<uint8_t> password_bytes(password.begin(), password.end());
    // run the algorithm 
    std::vector<uint8_t> key = PBKDF2::pbkdf2_hmac_sha256(password_bytes, salt, iterations, dkLen);

    // Package salt together with key as salt || key
    std::vector<uint8_t> packaged;
    packaged.reserve(salt.size() + key.size());
    packaged.insert(packaged.end(), salt.begin(), salt.end());
    packaged.insert(packaged.end(), key.begin(), key.end());

    return std::string(packaged.begin(), packaged.end());

}

/* std::string PBKDF2::pbkdf2_final(std::string password, std::string salt, int keyBits) 
Version of pbkdf2_final for a known salt, does not randomly generate salts. Takes in a password, a salt, and a number of keyBits, and converts to a hex string of that many keyBits that can be used as an AES key.*/
std::string PBKDF2::pbkdf2_final(std::string password, std::string salt, int keyBits) {
    // Validate keyBits matches your AES key sizes before doing any work
    if (keyBits != 128 && keyBits != 192 && keyBits != 256) {
        throw std::invalid_argument("keyBits must be 128, 192, or 256");
    }

    int dkLen = keyBits / 8;
    int iterations = 100000; 
    std::vector<uint8_t> salt_bytes = std::vector<uint8_t>(salt.begin(), salt.end());

    // Cast password to bytes 
    std::vector<uint8_t> password_bytes(password.begin(), password.end());
    // run the algorithm 
    std::vector<uint8_t> key = PBKDF2::pbkdf2_hmac_sha256(password_bytes, salt_bytes, iterations, dkLen);

    // Package salt together with key as salt || key
    std::vector<uint8_t> packaged;
    packaged.reserve(salt.size() + key.size());
    packaged.insert(packaged.end(), salt.begin(), salt.end());
    packaged.insert(packaged.end(), key.begin(), key.end());

    return std::string(packaged.begin(), packaged.end());
}



// tests with known values to check all is working 
/*int main(void) {
    std::cout << " ===== TESTING ALL HASHING FUNCTIONS ===== \n";

    std::string test1 = "abc";
    std::vector<uint8_t> test1_bytes = std::vector<uint8_t>(test1.begin(), test1.end());
    std::string output1 = BytesHex::bytes_to_hex(PBKDF2::sha256(test1_bytes));
    bool test1result = (output1 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    std::cout << "[" << (test1result ? "PASS" : "FAIL") << "] " << "\n"; 

    std::string test2_key = "key", test2_msg = "The quick brown fox jumps over the lazy dog";
    std::vector<uint8_t> test2_keybytes = std::vector<uint8_t>(test2_key.begin(), test2_key.end());
    std::vector<uint8_t> test2_msgbytes = std::vector<uint8_t>(test2_msg.begin(), test2_msg.end());
    std::string output2 = BytesHex::bytes_to_hex(PBKDF2::hmac_sha256(test2_keybytes, test2_msgbytes));
    bool test2result = (output2 == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
    std::cout << "[" << (test2result ? "PASS" : "FAIL") << "] " << "\n"; 

    std::string test3_pw = "password", test3_salt = "salt";
    std::vector<uint8_t> test3_pwbytes = std::vector<uint8_t>(test3_pw.begin(), test3_pw.end());
    std::vector<uint8_t> test3_saltbytes = std::vector<uint8_t>(test3_salt.begin(), test3_salt.end());
    std::string output3 = BytesHex::bytes_to_hex(PBKDF2::pbkdf2_hmac_sha256(test3_pwbytes, test3_saltbytes, 1, 32));
    bool test3result = (output3 == "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    std::cout << "[" << (test3result ? "PASS" : "FAIL") << "] " << "\n"; 

    std::string test4pw = "ae$%BM##15=6 test4";
    std::string hashed4 = PBKDF2::pbkdf2_final(test4pw, 256);
    std::vector<uint8_t> salt_bytes = std::vector<uint8_t>(hashed4.begin(), hashed4.begin() + 16);
    std::string salt = std::string(salt_bytes.begin(), salt_bytes.end());
    std::vector<uint8_t> test4pw_bytes = std::vector<uint8_t>(hashed4.begin() + 16, hashed4.end());
    std::string hashed4_check = PBKDF2::pbkdf2_final(test4pw, salt, 256);
    bool test4result = (hashed4 == hashed4_check);
    std::cout << "[" << (test4result ? "PASS" : "FAIL") << "] " << "\n"; 

    // test salts are randomized 
    std::string hashed5_first = PBKDF2::pbkdf2_final(test4pw, 256);
    std::string hashed5_second = PBKDF2::pbkdf2_final(test4pw, 256);
    bool salts_differ = (hashed5_first.substr(0, 16) != hashed5_second.substr(0, 16));
    std::cout << "[" << (salts_differ ? "PASS" : "FAIL") << "] two calls produce different random salts\n";

    return 0;
}*/


