# Radix commands

## Overview

| Command name | INS | Description |
| --- | --- | --- |
| `GET_VERSION` | 0x03 | Get application version as `MAJOR`, `MINOR`, `PATCH` |
| `GET_APP_NAME` | 0x04 | Get ASCII encoded application name |
| `GET_PUBLIC_KEY` | 0x05 | Get public key given BIP32 path |
| `SIGN_TX` | 0x06 | Parse, process and display contents of a raw transaction blob, sign it with key at a given BIP32 path |
| `SIGN_HASH` | 0x07 | Sign hash with key at a given BIP32 path |
| `ECDH` | 0x08 | Perform ECDH key exchange with your key at a given BIP32 path and a provided public key of some other party |

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

Signing of a transaction consists of at least `1 + I` many APDU packages, where `I` denotes the number of [Radix Engine Instructions](https://github.com/radixdlt/radixdlt-transaction-specs/blob/main/specs/parsing.md#transaction-format) in the transaction to sign. The first APDU package can well call *initial setup metadata*, and the following `I` APDU packages contain one single Radix Engine instruction each.

### Limitation

> ⚠️ This Ledger app **cannot** sign *any* transaction.
Please have a look at [TRANSACTION.md](TRANSACTION.md) for more information.

### Initial Setup Metadata APDU

The setup metadata package contains BIP32 path used to sign, the size (byte count) of the transaction (`tx_size`) as UInt32 and the number of Radix Engine Instructions in the transaction (`instruction_count`) as a UInt16. Finally it also contains an optional Human Readable Prefix (HRP) as the prefix for a RRI of a non XRD token being sent, a single byte specifying length of optional HRP is **always present**, having value `0` in case of no HRP.

This is a **limitation**, this Ledger App **only supports one non-XRD token per transaction**. The reason why we need to pass the HRP to the Ledger app in case of non-XRD token transfer is that this information is not included in the Radix blockchain ledger, it is a mere ui/ux construct. But since it is needed in order to properly format the Radix Resource Identifier (RRI), that uniquely identifies the token asset, being on [Bech32 format](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki), we send this to the Ledger app. The Ledger app will parse the RRI of token transfer instructions and identify which will need the HRP before being shown to the user on the Ledger device display.


#### Command


| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xAA | 0x06 |  0x77 | 0x00 | 1 + 4n +<br>4 + 2<br>+ 1(`HRP_LEN`) + `HRP_LEN`)| `len(bip32_path) (1)` \|\|<br> `bip32_path{1} (4)` \|\|<br>`...` \|\|<br>`bip32_path{n} (4)` \|\|<br>`tx_size (4)` \|\| `instruction_count (2)` \|\|<br>`hrp_len (1)` \|\| `hrp (var)` |


#### Response

The response `0x9000` (**Status Word** (`SW`) for `"OK"`) tells the host machine (TypeScript library) to proceed sending instructions.

If parsing of the intial setup metadata failed an error code from [`sw_custom.h`](../src/sw_custom.h) will be sent.

| Response length (bytes) | SW | RData |
| --- | --- | --- |
| 0 | 0x9000 | - |


### One APDU package per instruction

After the Ledger app have successfully parsed the intial setup metadata APDU and informed the host machine to start sending Radix Engine instruction, the host machine will send **only one Radix instruction per APDU**. Some Radix Engine instructions are as short as a single byte, so why not use the remaining 254 bytes? Well, it is a trade off between (perceived) effectiveness (utilizing all 255 bytes of data available per APDU package) vs simplicity (simple solution, being easy to understand and straightforward to code). We have chosen the latter. It is completely irrelevant that the host machine might be sending many APDUs to the Ledger device, since this is so fast that we humans do not even notice. The only "cost" of sending many small APDUs is that we need to implement the logic for parsing transactions in both C and [in TypeScript](https://github.com/radixdlt/radixdlt-javascript/tree/main/packages/tx-parser). We have decided that his cost is smaller than the cost of having much more complex C code (having to deal with instruction being cut in half between APDU packages and potentiall caching bytes is something we really want to avoid.).


#### Command

The `CData` contains the raw buffer of a single Radix Engine APDU instruction, e.g. `0a0001`, where the first byte `0a` denotes the instruction type `HEADER`, which should always be the first instruction in the transaction and `00` + `01` are *version* byte and *flag* respectively, and these values indicates that this transaction must not contain any instruction burning or minting any token, which is enforced by the Radix Core protocol.

| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xAA | 0x06 | 0x73 | 0x00 | var | var |


#### Response

In case of failure see `sw_custom.h` for error codes, otherwise we will either tell host machine to send the instruction if it was not the last, otherwise if it was the last we will respond with the signature and the produces hash.

**If parsed instruction was not the last**

| Response length (bytes) | SW | RData |
| --- | --- | --- |
| 0 | 0x9000 | - |

**If parsed instruction was the last**

| Response length (bytes) | SW | RData |
| --- | --- | --- |
| var | 0x9000 | `len(signature) (1)` \|\| <br> `signature (var)` \|\| <br> `v (1)`  \|\| <br> `hash (32)` |


## SIGN_HASH

### Command

| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xAA | 0x07 |  0x00 | 0x00 | <br> 0x80 (last) | 1 + 4n + 1 + h_len | `len(bip32_path) (1)` \|\|<br> `bip32_path{1} (4)` \|\|<br>`...` \|\|<br>`bip32_path{n} (4)` \|\|<br>h_len (1) \|\|<br>hash_digest (h_len) |

### Response

| Response length (bytes) | SW | RData |
| --- | --- | --- |
| var | 0x9000 | `len(signature) (1)` \|\| <br> `signature (var)` \|\| <br> `v (1)`|


## Status Words

See file `"sw.h"`