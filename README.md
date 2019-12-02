# Cryptopass
A CLI utility for generating long, unguessable passwords.

Program generates the password from:

 * Login (be it email, login, user ID... up to 127 bytes long),
 * Domain name of the resource where password is generated for,
 * Password length (1-32, default 25)
 * Master password

using 5000 iterations of PKDBF2-SHA256 algorithm.

## Features

 * Compatible with reference Cryptopass implementation (see "Prior Art")
 * Coded in pure C99 as console application
 * Does not require OpenSSL or any other third-party libraries
 * Can be compiled statically on any OS, including Android

## Prior art

 * [Original Chrome extension](https://chrome.google.com/webstore/detail/cryptopass/hegbhhpocfhlnjmemkibgibljklhlfco)
 * [Android port on F-Droid](https://f-droid.org/en/packages/krasilnikov.alexey.cryptopass/)
 * [C++ port by nikp123](https://github.com/nikp123/cryptopass)

## Used components

 * [Base64 encoder / decoder by Jouni Malinen](https://github.com/NS-K/hostapd/blob/master/src/utils/base64.c)
 * [fastpbkdf2 by Joseph Birr-Pixton](https://github.com/ctz/fastpbkdf2/tree/no-openssl)

## Usage

To invoke Cryptopass with all parameters, type:

```
cryptopass login domain.com 25
```

or just

```
cryptopass
```

to interactively specify the required information.

**NOTE: Master password (the password using to derive the application passwords) CAN NOT be specified on command-line! The user is expected to type it interactively!**

## Best practices on using Cryptopass

1. Consider using long passphrase (>30 letters, numbers, special chars) as master password. 
2. Do not use your master password anywhere else! Use it only for Cryptopass
3. Do not re-use the application passwords on different websites! Generate new password for every login on every resource!
4. Keep the master password safe and backed up. Also, it is good to keep the list of logins and domains along with the master passwords. The passwords generated by Cryptopass should NOT be remembered!
5. If the remote resource becomes breached, re-generate the password for that resource immediately and change the passwords as requested by resource owners.

And finally:
**Treat your passwords like underwear. Change them often and don’t share them with anybody!**

## Building

1. Clone the repository with Git:

    ```
    git clone https://github.com/basilgello/cryptopass
    ```

    or download the [master snapshot](https://github.com/basilgello/cryptopass/archive/master.zip) from Github if Git is not installed.

2. Build Cryptopass

    On POSIX-compliant operating systems supporting GNU Autotools, the build process is straghtforward:

    ```
    cd cryptopass
    autoreconf --install
    ./configure
    make
    make check
    make install
    ```

    To create static builds, do:

    ```
    cd cryptopass
    autoreconf --install
    ./configure
    make LDFLAGS="-static"
    make check LDFLAGS="-static"
    make install
    ```

    On systems with no GNU Autotools, build is also simple:

    ```
    gcc \
        -s -static \
        -o cryptopass-static \
        -DFASTPBKDF2_NOASM \
        -DHAVE_TERMIOS_H \
        -DNO_CONFIGURE_BUILD \
        -I lib/ \
        src/cryptopass.c \
        lib/fastpbkdf2/fastpbkdf2.c \
        lib/base64/base64.c
    ```

To create static builds for Android:

 * Download [Android NDK](https://developer.android.com/ndk/downloads)
 * Export path to NDK root as `NDK` environment variable, e.g:

   ```
   export NDK=/path/to/NDK/root
   ```

 * Compile the binary executable:

   ```
   cd cryptopass

   $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi16-clang \
        -s -static \
        -o cryptopass-armv7a-androideabi \
        -DFASTPBKDF2_NOASM \
        -DHAVE_TERMIOS_H \
        -DNO_CONFIGURE_BUILD \
        -I lib/ \
        src/cryptopass.c \
        lib/fastpbkdf2/fastpbkdf2.c \
        lib/base64/base64.c

   $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang \
        -s -static \
        -o cryptopass-aarch64v8a-androideabi \
        -DFASTPBKDF2_NOASM \
        -DHAVE_TERMIOS_H \
        -DNO_CONFIGURE_BUILD \
        -I lib/ \
        src/cryptopass.c \
        lib/fastpbkdf2/fastpbkdf2.c \
        lib/base64/base64.c
    ```

## Contributing

Contributions are welcome in form of Github pull requests (PRs).

## License

This program is licensed under Apache License 2.0.