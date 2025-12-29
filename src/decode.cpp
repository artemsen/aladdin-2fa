// SPDX-License-Identifier: MIT
// Decoders.
// Copyright (C) 2025 Artem Senichev <artemsen@gmail.com>

#include "decode.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <algorithm>
#include <memory>
#include <stdexcept>

std::vector<uint8_t> base32_decode(const std::string& encoded)
{
    const size_t max_decode_len = (encoded.length() * 5) / 8;
    std::vector<uint8_t> decoded;
    decoded.reserve(max_decode_len);

    uint8_t bits_remaining = 0;
    char current_byte = 0;

    for (const char enc_char : encoded) {
        uint8_t value;
        if (enc_char >= 'A' && enc_char <= 'Z') {
            value = enc_char - 'A';
        } else if (enc_char >= 'a' && enc_char <= 'z') {
            value = std::toupper(enc_char) - 'A';
        } else if (enc_char >= '2' && enc_char <= '7') {
            value = enc_char - '2' + ('Z' - 'A' + 1);
        } else if (enc_char == '=') {
            bits_remaining = 0;
            break; // padding character: end of encoded data
        } else {
            throw std::runtime_error("Invalid BASE32 data");
        }

        if (bits_remaining < 3) {
            current_byte |= value << (3 - bits_remaining);
            bits_remaining += 5;
        } else {
            current_byte |= value >> (bits_remaining - 3);
            decoded.push_back(current_byte);
            current_byte = value << (8 - (bits_remaining - 3));
            bits_remaining -= 3;
        }
    }

    // handle any remaining bits
    if (bits_remaining > 0 && decoded.size() < max_decode_len) {
        decoded.push_back(current_byte);
    }

    return decoded;
}

std::string base32_encode(const std::vector<uint8_t>& decoded)
{
    const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string encoded;
    size_t bits_collected = 0;
    uint32_t buffer = 0;

    for (const uint8_t datum : decoded) {
        // collect 8 bits of input data into a 32-bit buffer
        buffer = (buffer << 8) | datum;
        bits_collected += 8;

        // while we have at least 5 bits in the buffer, extract and encode them
        while (bits_collected >= 5) {
            // extract the top 5 bits
            uint32_t index = (buffer >> (bits_collected - 5)) & 0x1f;
            encoded.push_back(alphabet[index]);
            bits_collected -= 5;
        }
    }

    // handle remaining bits (padding)
    if (bits_collected > 0) {
        // shift remaining bits to the rightmost 5 bits of a group
        uint32_t index = (buffer << (5 - bits_collected)) & 0x1f;
        encoded.push_back(alphabet[index]);
    }

     // add padding characters '=' to ensure the output length is multiple of 8
     while (encoded.length() % 8 != 0) {
         encoded.push_back('=');
     }

    return encoded;
}

std::vector<uint8_t> base64_decode(const std::string& encoded)
{
    std::vector<uint8_t> decoded((encoded.length() * 3) / 4);

    // create base64 buffer from source web-safe format
    std::string encbuf = encoded;
    std::replace(encbuf.begin(), encbuf.end(), '-', '+');
    std::replace(encbuf.begin(), encbuf.end(), '_', '/');

    using BioHandle = std::unique_ptr<BIO, decltype(&BIO_free_all)>;
    BioHandle bio64(BIO_new(BIO_f_base64()), BIO_free_all);
    if (!bio64) {
        throw std::runtime_error("Unable to init BIO for BASE64");
    }
    BIO_set_flags(bio64.get(), BIO_FLAGS_BASE64_NO_NL);

    BIO* biomem = BIO_new_mem_buf(encbuf.data(), encbuf.length());
    if (!biomem) {
        throw std::runtime_error("Unable to init BIO for memory stream");
    }
    BIO_push(bio64.get(), biomem);

    const int data_sz = BIO_read(bio64.get(), decoded.data(), decoded.size());
    if (data_sz <= 0) {
        throw std::runtime_error("Invalid BASE64 data");
    }

    decoded.resize(data_sz);
    return decoded;
}

std::vector<uint8_t> aes128gcm_decode(const std::vector<uint8_t>& encoded,
                                      const std::vector<uint8_t>& key,
                                      const std::vector<uint8_t>& iv)
{
    const EVP_CIPHER* cipher = EVP_aes_128_gcm();
    if (EVP_CIPHER_key_length(cipher) != static_cast<int>(key.size())) {
        throw std::runtime_error("Invalid AES128 key size");
    }
    if (EVP_CIPHER_iv_length(cipher) != static_cast<int>(iv.size())) {
        throw std::runtime_error("Invalid AES128 IV size");
    }

    using EvpContext =
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
    EvpContext ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!EVP_DecryptInit_ex(ctx.get(), cipher, NULL, key.data(), iv.data())) {
        throw std::runtime_error("Unable initialize EVP decrypt");
    }

    std::vector<uint8_t> decoded(encoded.size());
    int len = decoded.size();
    if (!EVP_DecryptUpdate(ctx.get(), decoded.data(), &len, encoded.data(),
                           encoded.size())) {
        throw std::runtime_error("Unable to decrypt AES");
    }

    decoded.resize(len);
    return decoded;
}
