// SPDX-License-Identifier: MIT
// Program entry point.
// Copyright (C) 2025 Artem Senichev <artemsen@gmail.com>

#include <getopt.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "totp.hpp"

/**
 * Get default path for config file.
 * @return path to config file
 * @throws std::runtime_error on errors
 */
static std::filesystem::path defconfig_path()
{
    std::filesystem::path path;

    // get root config path for current user
    const char* xdg = std::getenv("XDG_CONFIG_HOME");
    if (xdg) {
        path = xdg;
    } else {
        const char* home = std::getenv("HOME");
        if (home) {
            path = home;
        } else {
            struct passwd* pw = getpwuid(getuid());
            if (pw && pw->pw_dir) {
                path = pw->pw_dir;
            }
        }
        if (!path.empty()) {
            path /= ".config";
        }
    }
    if (path.empty()) {
        throw std::runtime_error("Unknown config path");
    }

    // construct final path
    path /= "aladdin-2fa";
    path /= "totp.json";

    return path;
}

/**
 * Application entry point.
 */
int main(int argc, char* argv[])
{
    std::string config;
    const char* jticket = NULL;

    const struct option long_opts[] = {
        { "register", required_argument, NULL, 'r' },
        { "config",   required_argument, NULL, 'c' },
        { "version",  no_argument,       NULL, 'v' },
        { "help",     no_argument,       NULL, 'h' },
        { NULL,       0,                 NULL, 0   }
    };
    const char* short_opts = "r:c:vh";
    opterr = 0; // prevent native error messages

    // parse arguments
    int opt;
    while ((opt = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
        switch (opt) {
            case 'r':
                jticket = optarg;
                break;
            case 'c':
                config = optarg;
                break;
            case 'v':
                printf("Aladdin-2FA version " VERSION ".\n");
                return EXIT_SUCCESS;
            case 'h':
                puts("Aladdin-2FA (console version).");
                printf("Usage: %s [OPTION]\n", argv[0]);
                puts("  -r, --register=JASTICKET  Register new OTP");
                puts("  -c, --config=FILE         Path to custom OTP config");
                puts("  -v, --version             Print version info and exit");
                puts("  -h, --help                Print this help and exit");
                return EXIT_SUCCESS;
            default:
                fprintf(stderr, "Invalid argument: %s\n", argv[optind - 1]);
                return EXIT_FAILURE;
        }
    }
    if (optind < argc) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        return EXIT_FAILURE;
    }

    if (config.empty()) {
        config = defconfig_path();
    }

    try {
        totp otp;
        if (jticket) {
            otp.init(jticket);
            otp.save(config);
            puts("JAS ticket successfully registered.");
            printf("Config saved to file %s\n", config.c_str());
        } else {
            otp.load(config);
            printf("%0*d\n", static_cast<int>(otp.digits), otp.generate());
        }
    } catch (const std::exception& ex) {
        fprintf(stderr, "ERROR: %s\n", ex.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
