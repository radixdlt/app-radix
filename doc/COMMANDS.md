# Radix commands

## Overview

| Command name | INS | Description |
| --- | --- | --- |
| `GET_VERSION` | 0x03 | Get application version as `MAJOR`, `MINOR`, `PATCH` |
| `GET_APP_NAME` | 0x04 | Get ASCII encoded application name |
| `GET_PUBLIC_KEY` | 0x05 | Get public key given BIP32 path |
| `SIGN_TX` | 0x06 | Sign transaction given BIP32 path and raw transaction |

## GET_VERSION

### Command

| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xAA | 0x03 | 0x00 | 0x00 | 0x00 | - |

### Response

| Response length (bytes) | SW | RData |
| --- | --- | --- |
| 3 | 0x9000 | `MAJOR (1)` \|\| `MINOR (1)` \|\| `PATCH (1)` |

## GET_APP_NAME

### Command

| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xAA | 0x04 | 0x00 | 0x00 | 0x00 | - |

### Response

| Response length (bytes) | SW | RData |
| --- | --- | --- |
| var | 0x9000 | `APPNAME (var)` |

## GET_PUBLIC_KEY

### Command

| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xAA | 0x05 | 0x00 (no display) <br> 0x01 (display) | 0x00 | 1 + 4n | `len(bip32_path) (1)` \|\|<br> `bip32_path{1} (4)` \|\|<br>`...` \|\|<br>`bip32_path{n} (4)` |

### Response

| Response length (bytes) | SW | RData |
| --- | --- | --- |
| var | 0x9000 | `len(public_key) (1)` \|\|<br> `public_key (var)` \|\|<br> `len(chain_code) (1)` \|\|<br> `chain_code (var)` |

## SIGN_TX

### Command

| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xAA | 0x06 | 0x00-0x03 (chunk index) | 0x00 (more) <br> 0x80 (last) | 1 + 4n | `len(bip32_path) (1)` \|\|<br> `bip32_path{1} (4)` \|\|<br>`...` \|\|<br>`bip32_path{n} (4)` |

### Response

| Response length (bytes) | SW | RData |
| --- | --- | --- |
| var | 0x9000 | `len(signature) (1)` \|\| <br> `signature (var)` \|\| <br> `v (1)`|


## Status Words

See file `"sw.h"`