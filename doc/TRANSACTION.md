# Transaction

Overview of how the Radix Ledger app parses transactions, which transactions are supported. For more information on the format of the APDU packages for the Sign Tx flow, please see [COMMANDS.md](./COMMANDS.md).

## Limitation

> ⚠️ This Ledger app **cannot** sign *any* transaction, only these:
* Transfer tokens action.  
* Stake XRD to validator action.  
* Withdraw staked XRD from validator action.  
* Attached message action. 
* Any of combination of the actions above, with the restriction of **just one unique non-XRD token class in transfers**. I.e. the transaction **cannot** contain "Transfer 3 Zelda Coins" *and* "Transfer 5 Stella Coins".

I.e. all these transactions are valid:

**Single XRD transfer**
```
Transfer 1 XRD to Bob
```

**Single XRD transfer with attached message**
```
Transfer 2 XRD to Bob
Attach message: "Hey Bob, thanks for lunch" (possibly encrypted)
```

**Two XRD transfers**
```
Transfer 3 XRD to Carol
Transfer 5 XRD to Dan
```

**Single non-XRD transfer plus one XRD transfer**
```
Transfer 5 ZeldaCoin to Frank
Transfer 7 XRD to George
```

**Single stake action**
```
Stake 1024 XRD to validator FOO
```

**Unstake action plus two token transfers (one being non-XRD)**
```
Unstake 237 XRD from validator BAR
Transfer 25 StellaCoin to Ivan
Transfer 42 XRD to Jenny
```

Furthermore, the transaction must:
* Explicitly forbid minting of tokens
* Explicitly forbid burning of tokens (apart from transaction fee being paid in XRD)
* Explicitly state maximum allowed transaction fee


## Overview

The custom transaction deserialization/parsing presented follows [the Radix Transaction Specification found here](https://github.com/radixdlt/radixdlt-transaction-specs/blob/main/specs/parsing.md#transaction-format). Furthermore it mirrors the JavaScript/TypeScript middleware library implementation of the transaction parser, found in the [`@radixdlt/tx-parser` found here](https://github.com/radixdlt/radixdlt-javascript/tree/main/packages/tx-parser).

## Amount units

All amounts are UInt256 in atto (`E-18`) denomination, i.e. the amount of `1000 000 000 000 XRD` in a transaction is `0.000001 XRD`.

## Address format

Radix account addresses, validator address and resource identifiers (RRIs) are all displayed as [Bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) strings. The Bech32 encoding is encoding of Human Readable Prefix (HRP) and data (single instruction byte, or compressed public key, or trunacted hash of public key and some other data).

## Structure

### Transaction

A transaction is a list of Radix Engine instructions, some with fixed length, some of variable length. The Radix app does not need to care about where an instruction ends and another one starts, since we will always receive one and only one instruction at a time. It is the responsibility of the host machine to chunk the transaction up in its instructions and send then one at a time to this Ledger app.

### Variable length fiels (`bytes_t`)
Some fields within a single instruction might have variable length, e.g. `bytes_t` which consists of a single byte specifying the length of the payload. All this is specified in detail in the Radix Transaction Specification linked to above.


### Signature

Deterministic ECDSA ([RFC 6979](https://tools.ietf.org/html/rfc6979)) is used to sign transaction on the [SECP-256k1](https://www.secg.org/sec2-v2.pdf#subsubsection.2.4.1) curve.
The signed message is `m = sha256(sha256(tx_bytes))`.

### Fee

The transaction is **required** to contain a specific instruction specifying the transaction fee.