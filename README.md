# Radix Ledger app

This is a [Radix DLT](https://www.radixdlt.com/) Ledger Nano S and X app.


> ⚠️  Building the app from source is only confirmed to be working on Ubuntu 20.04, but should probably work on 18.04 as well ⚠️

> ☣️ ONLY USE A DEDICATED DEVELOPMENT LEDGER DEVICE. DO NOT USE ONE WITH "FUNDS ON" ☣️


# Setup development

Here is the official [Getting Started](https://ledger.readthedocs.io/en/latest/userspace/introduction.html) guide for a dev environment. 


> ⚠️ The official guide is not updated and does not work properly for Nano S with firmware 2.0.0 nor with Ledger Nano X. ⚠️
> PLEASE FOLLOW THE GUIDE IN THIS `README`INSTEAD.


## Locations

Create `/opt/bolos-devenv`

This will be our `BOLOS_ENV` location, referenced to by all steps below.

## Two SDKS

> ⚠️ Nano S with a firmware older than 2.0.0 is NOT supported ⚠️
> You MUST have installed firmware SE 2.0.0 on your Ledger Nano S.
> Note that the Nano S SDK has a matching named version, 2.0.0, but Ledger Nano X has a different SDK with version 1.2.4.


### `Nano S` SDK
1. Download [`Nano S` SDK 2.0.0 (2.0.0-1)](https://github.com/LedgerHQ/nanos-secure-sdk/releases/tag/2.0.0-1), which only works with Ledger Nano S, and only with firmware SE 2.0.0.
2. Unarchive.
3. Change name of the folder to `nano_s_sdk_se200`.
4. Move the folder to the folder `/opt/bolos-devenv/`.

### `Nano X` SDK
1. Download [`Nano X` SDK 1.2.4 (1.2.4-5.1)](https://github.com/LedgerHQ/nanox-secure-sdk/releases/tag/1.2.4-5.1), which only works with Ledger Nano X, and only with firmware SE 1.2.4.
2. Unarchive.
3. Change name of the folder to `nano_x_sdk_se124`.
4. Move the folder to the folder `/opt/bolos-devenv.`.

## Clang

### `Nano S` compatible `clang 10`
1. Download [`clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04`](https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0/clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz) (works with Ubuntu 20.04), which we will use for Nano S, with firmware SE 2.0.0 (2.0.0-1).
2. Unarchive.
3. Change name of folder to `nanos_se200_clang_10`.
4. Move the folder to the folder `/opt/bolos-devenv.`.

### `Nano S` compatible `clang 9` 
1. Download [`clang+llvm-9.0.0-x86_64-linux-gnu-ubuntu-18.04`](https://releases.llvm.org/9.0.0/clang+llvm-9.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz) (works with Ubuntu 20.04), which we will use for Nano X, with firmware SE 1.2.4 (1.2.4-5.1).
2. Unarchive.
3. Change name of folder to `nanox_se124_clang_9`.
4. Move the folder to the folder `/opt/bolos-devenv.`.

(There is also a verion available for Ubuntu 19.04, **this has not been tested**, but might work).


> ⚠️ ONLY these versions of `clang` are **confirmed** to be working with Ledger Nano S and X respectively (newer versions _might_ work.) ⚠️

## GCC

1. Download [`gcc-arm-none-eabi-10-2020-q4-major-x86_64-linux`](https://developer.arm.com/-/media/Files/downloads/gnu-rm/10-2020q4/gcc-arm-none-eabi-10-2020-q4-major-x86_64-linux.tar.bz2?revision=ca0cbf9c-9de2-491c-ac48-898b5bbc0443&la=en&hash=68760A8AE66026BCF99F05AC017A6A50C6FD832A)
2. Unarchive
3. Change the name of the folder to `gcc_nano_s_se200_and_nano_x_se124_compatible`.
4. Move the folder to the folder `/opt/bolos-devenv.`.

## Locations

```sh
➜  bolos-devenv pwd
/opt/bolos-devenv
➜  bolos-devenv ls
gcc_nano_s_se200_and_nano_x_se124_compatible
nano_s_sdk_se200
nanos_se200_clang_10
nano_x_sdk_se124
nanox_se124_clang_9
venv_ledger
```

`venv_ledger` can be put anywhere really, more about that later.

## ENV

Edit your `~/.zshrc` and declare these values.

```sh
# LEDGER DEV
export BOLOS_ENV=/opt/bolos-devenv
export BOLOS_SDK_NANO_S=$BOLOS_ENV/nano_s_sdk_se200
export BOLOS_SDK_NANO_X=$BOLOS_ENV/nano_x_sdk_se124

# clang-arm-fropi
export CLANGPATH_NANO_S=$BOLOS_ENV/nanos_se200_clang_10 
export CLANGPATH_NANO_X=$BOLOS_ENV/nanox_se124_clang_9

export SCP_PRIVKEY=b5b2eacb2debcf4903060e0fa2a139354fe29be9e4ac7c433f694a3d93297eaa
```

## Installer

We use `ledgerblue` for installing built binaries onto your Ledger Nano S and configuring of the Ledger device.

> ⚠️ Installing apps onto Ledger Nano X is not supported. ONLY `S` will work! ⚠️ 

### Install Python3
Install Python 3.

### virtualenv
1. Create a virtual env, I named it `venv_ledger` and put it in `/opt/bolos-devenv`.
2. Activate the virtual env before you build and load apps! `source <PATH_TO_VENV>/bin/activate`

> ⚠️ You should activate the virtual env in order to install `ledgerblue` and compile and load apps.  ⚠️ 


### `ledgerblue`

Install [`ledgerblue`](https://github.com/LedgerHQ/blue-loader-python) by following the README guide.


## Set dev `mnemonic`

> ☣️ ONLY USE A DEDICATED DEVELOPMENT LEDGER DEVICE. DO NOT USE ONE WITH "FUNDS ON" ☣️

With your Ledger device started in `recovery mode`, call `hostOnboard` below.

```sh
python3 -m ledgerblue.hostOnboard --apdu --id 0 --prefix "" --passphrase "" --pin 5555 --words "equip will roof matter pink blind book anxiety banner elbow sun young"
```

Do this so that you will get the same HD wallet as the rest of the developers, so that integration tests will work (e.g. in TypeScript library).

## PIN bypass [Optional]
Optionally, to skip having to enter PIN to opened the app you can [follow this guide](https://ledger.readthedocs.io/en/latest/userspace/debugging.html#pin-bypass)

Export this variable in your `~/.zshrc`: 

```sh
export SCP_PRIVKEY=b5b2eacb2debcf4903060e0fa2a139354fe29be9e4ac7c433f694a3d93297eaa
```

With your Ledger device started in `recovery mode`, call `setupCustomCA` below, check the [`targetID` here](https://gist.github.com/TamtamHero/b7651ffe6f1e485e3886bf4aba673348) (`Nano S: 0x31100004` and `Nano X: 0x33000004`)

```sh
python3 -m ledgerblue.setupCustomCA --targetId TARGET_ID_GOES_HERE --public 0422c5e9a8156db284d660eca98cc849aa8326a33361068d2b6c394fd2a93cb3803175f5b35ec1bda4471895c4c002bd859ca8e08b69f555164ba5d8d35e2dbc7f --name RadixDev
```

### Pre-release

#### Prerequisites
If you want to install [a pre-built binary from _Releases_](github.com/radixdlt/app-radix/releases) make sure you have performed the steps beginning from [Installer](#Installer) above. **You should skip the `Set dev mnemonic` step!** 

Make sure you have:
* ...sourced virtual env (see [virtualenv](#virtualenv) above).
* ...installed `ledgerblue` (see [ledgerblue](#ledgerblue) above).
* Unzipped the two folder` _bin_ and _debug_ from the downloaded achive from Releases.
* That your working directory contains the _bin_ and _debug_ folders.


#### Install
(have you done everything according to [Prerequisites](#Prerequisites) above?)

Run:

```sh
python -m ledgerblue.loadApp \
--path "44'/536'" \
--curve secp256k1 \
--tlv \
--targetId 0x31100004 \
--delete \
--fileName bin/app.hex \
--appName Radix \
--dataSize $((0x`cat debug/app.map |grep _envram_data | tr -s ' ' | cut -f2 -d' '|cut -f2 -d'x'` - 0x`cat debug/app.map |grep _nvram_data | tr -s ' ' | cut -f2 -d' '|cut -f2 -d'x'`)) \
--icon 010000000000ffffffffffffffffffffffffe1ffe1fffc7ffc47fe4ffe1fff3fffffffffffffffffff
```

Which will display scary warnings like: 
```sh
Generated random root public key : b'04792b376a72669727c910272b35a406b85e296ec947248e52dc73fdc9cf8878f3be857ae8b4436363a95681932a5ba65ed739dc5545160c3d404c600b2131425f'
Using test master key b'04792b376a72669727c910272b35a406b85e296ec947248e52dc73fdc9cf8878f3be857ae8b4436363a95681932a5ba65ed739dc5545160c3d404c600b2131425f'
Using ephemeral key b'040dd62506adf4b144406cb0318f85510e30da66552b167ed35ed2a513c0613c0e4d33d2122f88e9dd05134f4b056000d4ea5a71001829990d265b3a3e5bb5df31'
Broken certificate chain - loading from user key
Target version is not set, application hash will not match!
```

Which you can ignore.

#### Uninstall
(have you done everything according to [Prerequisites](#Prerequisites) above?)

```sh
python -m ledgerblue.deleteApp \
--targetId 0x31100004 \
--appName Radix
```


# Compilation and installation

## Nano S

```sh
make DEBUG=1  # compile optionally with PRINTF
make load     # load the app on the Nano using Python pkg `ledgerblue`
```

> 💡 When compiling against Nano S you should not get any warnings.

## Nano X

```sh
make TARGET=NANOX DEBUG=1
make TARGET=NANOX load
```

> 💡 When compiling against Nano X, you will get MANY warnings, looking like this

```sh
/opt/bolos-devenv/nano_x_sdk_se124/src/os_io_seproxyhal.c:309:9: warning: declaration does not declare anything [-Wmissing-declarations]
        __attribute__((fallthrough));
        ^
/opt/bolos-devenv/nano_x_sdk_se124/src/os_io_seproxyhal.c:321:9: warning: declaration does not declare anything [-Wmissing-declarations]
        __attribute__((fallthrough));
        ^
/opt/bolos-devenv/nano_x_sdk_se124/src/os_io_seproxyhal.c:392:3: warning: implicit declaration of function 'check_audited_app' is invalid in C99 [-Wimplicit-function-declaration]
  check_audited_app();
  ^
/opt/bolos-devenv/nano_x_sdk_se124/src/os_io_seproxyhal.c:1102:13: warning: declaration does not declare anything [-Wmissing-declarations]
            __attribute__((fallthrough));
            ^
/opt/bolos-devenv/nano_x_sdk_se124/src/os_io_seproxyhal.c:1361:7: warning: declaration does not declare anything [-Wmissing-declarations]
      __attribute__((fallthrough));
      ^
5 warnings generated.
[CC]	  obj/os_io_usb.o
[CC]	  obj/os_printf.o
/opt/bolos-devenv/nano_x_sdk_se124/src/os_printf.c:958:21: warning: declaration does not declare anything [-Wmissing-declarations]
                    __attribute__((fallthrough));
                    ^

```

# Uninstall
Call `make delete` to uninstall app.

# Troubleshooting

### USB connection
Follow [the offical troubleshooting guide for USB issues here](https://support.ledger.com/hc/en-us/articles/360019301813-Fix-USB-issues) (expand `Linux` section).

Alternatively [the Ledger manual PDF here might give some clues](https://github.com/LedgerHQ/openpgp-card-app/blob/master/doc/user/blue-app-openpgp-card.pdf) (see section 0.3.2.1 for `Linux`)

#### Quit Ledger Live on host machine
Your computer (a.k.a. host machine) will fail to make a connection to the Ledger if you have the desktop app Ledger Live running.

#### Quit Radix App on Ledger device
Quit the Radix app on the Ledger device when you want to install a new version of it.


### ENV
Use `printenv` to display your ENV variables, if they are not correctly setup to match expected values of the [`Makefile`](./Makefile) in the root of this project, then compilation will not work.

I had accidently set conflicing values in `/etc/environment` (I have no clue how...).

### Firmware
1. Make sure you have Secure Elements (SE) Firmware 2.0.0 installed.
2. Make sure you DO NOT install incompatible DEBUG Firmware on your Ledger. The [one mentioned in the guide](https://ledger.readthedocs.io/en/latest/userspace/debugging.html) is only for SE 1.6.0.


### `targetID`
Make sure you are using the correct `targetId` for Ledger Nano S/X.

# Documentation

High level documentation such as [APDU](doc/APDU.md), [commands](doc/COMMANDS.md) and [transaction serialization](doc/TRANSACTION.md) are included in developer documentation which can be generated with [doxygen](https://www.doxygen.nl)

```sh
doxygen .doxygen/Doxyfile
```

the process outputs HTML and LaTeX documentations in `doc/html` and `doc/latex` folders.

# Tests & Continuous Integration

The flow processed in [GitHub Actions](https://github.com/features/actions) is the following:

- Code formatting with [clang-format](http://clang.llvm.org/docs/ClangFormat.html)
- Compilation of the application for Ledger Nano S in [ledger-app-builder](https://github.com/LedgerHQ/ledger-app-builder)
- Unit tests of C functions with [cmocka](https://cmocka.org/) (see [unit-tests/](unit-tests/))
- End-to-end tests with [Speculos](https://github.com/LedgerHQ/speculos) emulator (see [tests/](tests/))
- Code coverage with [gcov](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html)/[lcov](http://ltp.sourceforge.net/coverage/lcov.php) and upload to [codecov.io](https://about.codecov.io)
- Documentation generation with [doxygen](https://www.doxygen.nl)

It outputs 4 artifacts:

- `radix-app-debug` within output files of the compilation process in debug mode
- `speculos-log` within APDU command/response when executing end-to-end tests
- `code-coverage` within HTML details of code coverage
- `documentation` within HTML auto-generated documentation