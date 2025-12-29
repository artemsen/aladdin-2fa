// SPDX-License-Identifier: MIT
// Time-Based One-Time Password.
// Copyright (C) 2025 Artem Senichev <artemsen@gmail.com>

#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

// Time-Based One-Time Password
struct totp {
    /**
     * Register ticket on JaCarta Authentication Server (JAS).
     * @param ticket JAS ticket to register
     * @throws std::runtime_error on errors
     */
    void init(const char* ticket);

    /**
     * Load TOTP parameters from config file.
     * @param config path to config file to read
     * @throws std::runtime_error on errors
     */
    void load(const std::filesystem::path& config);

    /**
     * Save TOTP parameters to config file.
     * @param config path to config file to write
     * @throws std::runtime_error on errors
     */
    void save(const std::filesystem::path& config) const;

    /**
     * Generate TOTP code.
     * @param encoded source string to decode
     * @return TOTP code for current time
     * @throws std::runtime_error on errors
     */
    uint32_t generate() const;

    std::vector<uint8_t> key; ///< TOTP key
    std::string algorithm;    ///< Hash algorithm name
    size_t digits;            ///< Number of digits in TOTP code
    size_t period;            ///< TOTP period in seconds
};
