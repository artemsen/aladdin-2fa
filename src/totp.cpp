// SPDX-License-Identifier: MIT
// Time-Based One-Time Password.
// Copyright (C) 2025 Artem Senichev <artemsen@gmail.com>

#include "totp.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <time.h>

#include <fstream>
#include <stdexcept>

#include "decode.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include <json.hpp>
using json = nlohmann::json;

#include <uri_parser.h>

// Ticket for JaCarta Authentication Server (JAS)
struct jas_ticket {
    std::string request_id;
    std::string address;
    std::vector<uint8_t> key;

    /**
     * Constructor.
     * @param ticket JAS ticket to register
     * @throws std::runtime_error if ticket has invalid format
     */
    jas_ticket(const std::string& ticket)
    {
        uri::Uri uri = uri::parse_uri(ticket);
        if (uri.error != uri::Error::None || uri.scheme != "jasticket") {
            throw std::runtime_error("Invalid JAS ticket: expected string "
                                     "started with jasticket://");
        }
        if (uri.authority.host.empty() || !uri.query.contains("address") ||
            !uri.query.contains("key")) {
            throw std::runtime_error("Invalid JAS ticket: " + ticket);
        }

        request_id = uri.authority.host;
        address = uri.query.at("address");

        try {
            key = base32_decode(uri.query.at("key"));
        } catch (const std::runtime_error& ex) {
            throw std::runtime_error("Invalid JAS ticket: bad key format");
        }
    }

    /**
     * Register ticket on JAS server.
     * @return JAS response with TOTP parameters
     * @throws std::runtime_error on errors
     */
    std::string register_ticket() const
    {
        // prepare registration request
        json request;
        request["reqID"] = request_id;
        const std::string request_body = request.dump();

        // send registration request to JAS server
        httplib::Client jas_client(address);
        const httplib::Result response =
            jas_client.Post("/register", request_body.c_str(),
                            request_body.length(), "application/json");
        if (!response) {
            throw std::runtime_error("Network error");
        }

        const std::string& ctype = response->get_header_value("Content-Type");

        // handle response errors
        if (response->status != httplib::OK_200) {
            if (ctype != "application/json") {
                throw std::runtime_error("Status " +
                                         std::to_string(response->status));
            }
            const json jr = json::parse(response->body);
            if (jr.contains("message")) {
                std::string message = jr["message"].get<std::string>();
                std::replace(message.begin(), message.end(), '\n', ' ');
                throw std::runtime_error(message);
            } else {
                throw std::runtime_error("Status " +
                                         std::to_string(response->status));
            }
        }
        if (ctype != "application/json") {
            throw std::runtime_error("Invalid content type");
        }

        // handle registration response
        const json jr = json::parse(response->body);
        if (!jr.contains("mobileotp")) {
            throw std::runtime_error("Node 'mobileotp' not found");
        }
        const std::string mobileotp = jr["mobileotp"].get<std::string>();

        // get IV and encrypted data
        std::vector<std::string> otp_parts;
        size_t start = 0, end;
        while ((end = mobileotp.find('.', start)) != std::string::npos) {
            otp_parts.push_back(mobileotp.substr(start, end - start));
            start = end + 1;
        }
        otp_parts.push_back(mobileotp.substr(start));
        if (otp_parts.size() < 2) {
            throw std::runtime_error("Incorrect OTP response format");
        }
        const std::vector<uint8_t> iv = base64_decode(otp_parts[0]);
        const std::vector<uint8_t> crypt = base64_decode(otp_parts[1]);

        // decrypt message and add last null
        std::vector<uint8_t> decoded = aes128gcm_decode(crypt, key, iv);
        decoded.push_back(0);

        // get TOTP params from response
        const json totp_params = json::parse(decoded);
        if (!totp_params.contains("otp")) {
            throw std::runtime_error("Node 'otp' not found");
        }
        return totp_params["otp"].get<std::string>();
    }
};

void totp::init(const char* ticket)
{
    try {
        jas_ticket jt(ticket);
        const std::string otp = jt.register_ticket();

        uri::Uri uri = uri::parse_uri(otp);
        if (uri.error != uri::Error::None || !uri.query.contains("secret") ||
            !uri.query.contains("algorithm") || !uri.query.contains("digits") ||
            !uri.query.contains("period")) {
            throw std::runtime_error("Invalid OTP response: " + otp);
        }

        key = base32_decode(uri.query.at("secret"));
        algorithm = uri.query.at("algorithm");
        digits = std::stoul(uri.query.at("digits"));
        period = std::stoul(uri.query.at("period"));
    } catch (const std::runtime_error& ex) {
        throw std::runtime_error(
            std::string("Failed to register ticket on JAS server: ") +
            ex.what());
    }
}

void totp::save(const std::filesystem::path& config) const
{
    // create parent dir
    const std::filesystem::path parent = config.parent_path();
    if (!std::filesystem::exists(parent)) {
        std::filesystem::create_directories(parent);
    }

    // serialize to json
    json cfg_json;
    cfg_json["key"] = base32_encode(key);
    cfg_json["algorithm"] = algorithm;
    cfg_json["digits"] = digits;
    cfg_json["period"] = period;

    // write to file
    std::ofstream cfg_file(config);
    if (!cfg_file) {
        throw std::runtime_error("Error writing file " + config.string());
    }
    cfg_file << std::setw(4) << cfg_json << '\n';
}

void totp::load(const std::filesystem::path& config)
{
    if (!std::filesystem::exists(config)) {
        std::string message = "Config file not found: " + config.string();
        message += "\nHave you registered your JAS ticket?";
        throw std::runtime_error(message);
    }

    // read and parse json
    std::ifstream cfg_file(config);
    if (!cfg_file) {
        throw std::runtime_error("Error reading file " + config.string());
    }
    json cfg_json = json::parse(cfg_file);

    // restore state from json
    key = base32_decode(cfg_json["key"].get<std::string>());
    algorithm = cfg_json["algorithm"].get<std::string>();
    digits = cfg_json["digits"].get<size_t>();
    period = cfg_json["period"].get<size_t>();
}

uint32_t totp::generate() const
{
    const uint64_t seconds = time(NULL);
    const uint64_t otp_base = seconds / period;

    const uint8_t otp_data[] = {
        static_cast<uint8_t>((0xff00000000000000 & otp_base) >> 56),
        static_cast<uint8_t>((0x00ff000000000000 & otp_base) >> 48),
        static_cast<uint8_t>((0x0000ff0000000000 & otp_base) >> 40),
        static_cast<uint8_t>((0x000000ff00000000 & otp_base) >> 32),
        static_cast<uint8_t>((0x00000000ff000000 & otp_base) >> 24),
        static_cast<uint8_t>((0x0000000000ff0000 & otp_base) >> 16),
        static_cast<uint8_t>((0x000000000000ff00 & otp_base) >> 8),
        static_cast<uint8_t>((0x00000000000000ff & otp_base) >> 0),
    };

    // define hash algorithm
    const EVP_MD* mda;
    if (algorithm == SN_sha512) {
        mda = EVP_sha512();
    } else if (algorithm == SN_sha256) {
        mda = EVP_sha256();
    } else if (algorithm == SN_sha1) {
        mda = EVP_sha1();
    } else {
        throw std::runtime_error("Unknown hash algorithm: " + algorithm);
    }

    // calculate hmac
    uint8_t hash[EVP_MAX_MD_SIZE];
    unsigned int len;
    HMAC(mda, key.data(), key.size(), otp_data, sizeof(otp_data), hash, &len);

    const uint8_t offset = hash[len - 1] & 0xf;
    // clang-format off
    const uint32_t binary =
        ((hash[offset + 0] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8)  |
        ((hash[offset + 3] & 0xff) << 0);
    // clang-format on

    // calculate the divisor used to reduce the size of the OTP code
    uint32_t divisor;
    if (digits == 6) {
        divisor = 1000000;
    } else if (digits == 7) {
        divisor = 10000000;
    } else if (digits == 8) {
        divisor = 100000000;
    } else {
        throw std::runtime_error("Unsupported digits number");
    }

    // final OTP code
    const uint32_t otp = binary % divisor;

    return otp;
}
