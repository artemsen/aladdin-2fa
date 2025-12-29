// SPDX-License-Identifier: MIT
// Decoders.
// Copyright (C) 2025 Artem Senichev <artemsen@gmail.com>

#pragma once

#include <cstdint>
#include <string>
#include <vector>

/**
 * Decode Base32 string.
 * @param encoded source string to decode
 * @return decoded data
 * @throws std::runtime_error if encoded data is invalid
 */
std::vector<uint8_t> base32_decode(const std::string& encoded);

/**
 * Decode binary data to Base32 string.
 * @param decoded source string to encode
 * @return encoded data
 */
std::string base32_encode(const std::vector<uint8_t>& decoded);

/**
 * Decode Base64 string.
 * @param encoded source string to decode
 * @return decoded data
 * @throws std::runtime_error if encoded data is invalid
 */
std::vector<uint8_t> base64_decode(const std::string& encoded);

/**
 * Decode source buffer with AES128 GCM algo.
 * @param encoded source buffer to decode
 * @param key buffer with AES key
 * @param iv buffer with IV data
 * @return decoded data
 * @throws std::runtime_error if key or IV are invalid, or other error occurred
 */
std::vector<uint8_t> aes128gcm_decode(const std::vector<uint8_t>& encoded,
                                      const std::vector<uint8_t>& key,
                                      const std::vector<uint8_t>& iv);
