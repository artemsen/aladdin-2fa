# Aladdin 2FA console

An unofficial port of the [Aladdin-2FA](https://www.aladdin-rd.ru/catalog/aladdin-2fa)
Linux application with removed dependencies on X11 and OpenGL, but with console
support.

The current version has limited functionality and can only:
- Register OTP tickets on the JaCarta authentication server;
- Store OTP parameters in config file;
- Generate OTP code.

## Usage

Before generating OPT codes, you need to register on the JAS server by
specifying your ticket in the `--register` parameter:

```shell
$ aladdin-2fa --register="jasticket://123456789...."
JAS ticket successfully registered.
Config saved to file /home/user/.config/aladdin-2fa/totp.json
```

After registration, TOTP parameters will be saved in the configuration file, by
default it is located in `${HOME}/.config/aladdin-2fa/totp.json`. The file path
can be overridden using the `--config` parameter.
Please note that this file contains a unique key used to generate OTP codes, so
it should only be accessible to you.

OTP generation:
```shell
$ aladdin-2fa
123456
```

## Build

To build the project you will need:
- C++ compiler with support for the C++20 standard;
- Meson build system;
- OpenSSL library (libssl and libcrypto).

```shell
meson setup my_build_dir
meson compile -C my_build_dir
meson install -C my_build_dir
```
