# Pysatochip 

  Licence: LGPL v3
  Author: Toporin
  Language: Python (>= 3.6)
  Homepage: https://github.com/Toporin/pysatochip

## Introduction

The Pysatochip library allows to integrate the Satochip Hardware Wallet with a client wallet such as electrum. To use it, you need a device with the Satochip javacard applet installed (see https://github.com/Toporin/SatochipApplet). If the wallet is not intialized yet, the wallet can perform the setup (you only need to do this once). During setup, a seed is created: this seed allows you to recover your wallet at anytime, so make sure to BACKUP THE SEED SECURELY! During setup, a PIN code is also created: this PIN allows to unlock th device to access your funds. If you try too many wrong PIN, your device will be locked indefinitely (it is 'bricked'). If you loose your PIN or brick your device, you can only recover your funds with the seed backup.

The Satochip wallet is currently in Beta, use with caution! In this phase, it is strongly recommended to use the software on the Bitcoin testnet first.
This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.

Remark: Pysatochip uses Python 3.x. In case of error, check first that you are not trying to run with Python 2.x or with Python 2.x libraries.

### Satochip 2-Factor-Authentication (2FA)

Satochip-2FA is an optional feature that allows to use 2-Factor-Authentication in conjonction with the Satochip hardware wallet. When enabled, transaction requests are sent to an app on a second device for approval before signing them with the Satochip. For security, once enabled, the 2FA can only be disabled when the seed is reset. Be sure to keep a copy of the 2FA key in a safe location. 

​When enabled, a secret key is shared via a qr-code between the satochip and a second device (currently, only Android). The app then regularly polls the Electrum server for new transaction proposals. These transaction candidates are then parsed and displayed on the second device. If approved, a cryptographic code is sent back to securely and uniquely approve the transaction so that the satochip can sign it.

## Installing this Module

This module is available for download on PyPy with the command `pip3 install pysatochip`.

You can install this module on your system with the command `python setup.py install`.

To use the Command Line Interface, you need to install additional dependencies, use this command instead: `pip install "pysatochip[CLI]"` or `pip install -e ".[CLI]"` (local install). 

### Cryptographic backend

All operations involving a private key (the card secure channel's ECDH key exchange, and signing) run on
a side-channel-hardened implementation. pysatochip picks one automatically:

1. [`cryptography`](https://cryptography.io) (pyca/OpenSSL) — the default, installed as a normal dependency.
2. [libsecp256k1](https://github.com/bitcoin-core/secp256k1) through [`embit`](https://pypi.org/project/embit/)
   — used when `cryptography` is unavailable, which is typically the case on embedded builds such as
   seedsigner-os. Install it with `pip install "pysatochip[embedded]"`.

If neither is present, pysatochip raises an error on any private-key operation rather than falling back to
a vulnerable implementation; signature verification continues to work. The pure-python `ecdsa` package is
no longer used or required, as it is affected by
[CVE-2024-23342](https://github.com/tlsfuzzer/python-ecdsa/issues/330) — see
[issue #8](https://github.com/Toporin/pysatochip/issues/8).


## Command Line Interface
Once you have installed the module, you can access its functionality through a command line client `satochip-cli`.

There are a wide range of available commands, each with their own relevant options. The best way to find these is with the `--help` argument. (`satochip-cli --help`)

_There are also some general tools, such as those required to decrypt encrypted Seedkeeper JSON backups. (These can be accessed either standalone or via the module)_

### Card Authenticity Check

Use the `common-verify-authenticity` command to verify that the connected card was issued by Satochip:

```
satochip-cli common-verify-authenticity
```

By default the command relies on OpenSSL for certificate validation. If OpenSSL is not available, it falls back to a pure Python implementation using `pycryptodomex`. You can force a specific backend with the `--backend` option, choosing between `auto`, `openssl`, or `pycryptodomex`:

```
satochip-cli common-verify-authenticity --backend pycryptodomex
```


More details about the `satochip-cli` [here](https://github.com/Toporin/pysatochip/blob/master/README-CLI.md).

## Running from Source

If you don't want to install the pysatochip module, you can also run a number of tools direcly from the repository folder.

**Command Line Tool:** `python satochip_cli.py`

**SatoChip Hardware Test** `python test_satochip.py`

**SeedKeeper Hardware Test** `python test_seedkeeper.py`

## Running the Tests

The suite in `tests/` needs no hardware and runs in a few seconds:

```
python tests/run_all.py
```

Or with stdlib discovery, from the repository root:

```
python -m unittest discover -s tests -t .
```

To narrow things down, any test file can be run directly, and you can select a single class or method:

```
python tests/test_ec_backend.py
python tests/test_ec_backend.py TestECDH
python tests/test_ec_backend.py TestECDH.test_shared_secret_matches_frozen_vector
```

| File | Covers |
|---|---|
| `test_ec_backend.py` | ECDH, key derivation, signing, verification and public key recovery, run against every available backend |
| `test_ec_math.py` | Curve arithmetic, signature encoding, DER strictness |
| `test_ecc.py` | The `ECPubkey` / `ECPrivkey` public API |
| `test_secure_channel.py` | The ECDH handshake and AES layer, against a simulated applet |
| `test_certificate_validator.py` | Both legs of the certificate chain, including the shipped CA certificates |
| `test_backend_scenarios.py` | Whole-environment checks with dependencies deliberately made unimportable |
| `test_bip340.py` | BIP340 schnorr signing and verification, and the BIP341 taproot tweak, against the official vectors |

### Backend coverage

Most tests run once per available backend, so what gets exercised depends on what is installed. With only
`cryptography` you will see `OK (skipped=11)`: the libsecp256k1 and cross-backend tests skip themselves.
Install the optional backend to cover both:

```
pip install "pysatochip[embedded]"
```

`test_backend_scenarios.py` covers the single-backend cases either way, by blocking imports in a
subprocess. It is what verifies that pysatochip still works on a build with neither `cryptography` nor
pyOpenSSL available, and that a private-key operation fails loudly when no hardened backend is present.

### Regression vectors

`tests/vectors.py` holds secp256k1 values captured from the pre-0.18.0 implementation. `ECDH_SHARED_X` in
particular pins the card secure-channel wire format: the applet derives the same shared secret on its
side, so if that value ever changes, every Satochip / SeedKeeper / Satodime session breaks. Treat a
failure there as a compatibility break rather than a broken test.

`tests/_gen_vectors.py` records how those vectors were produced, against the old `ecdsa` implementation.
It refuses to run on the current tree, because signing is no longer deterministic here and it would emit
signature values that do not match the ones being pinned. To audit a vector, check out the previous
release instead:

```
git checkout v0.17.4 && pip install ecdsa && python tests/_gen_vectors.py
```

### BIP340 / BIP341 vectors

`tests/vectors_bip340.py` holds the official taproot vectors, transcribed verbatim from upstream:
`bip-0340/test-vectors.csv`, `bip-0341/wallet-test-vectors.json` and the BIP86 test vectors. They pin
`tests/bip340_ref.py`, a pure-python BIP340/BIP341 reference built on `ec_math.py` alone, so it needs no
dependency beyond the library itself (`cryptography` does not expose schnorr or x-only operations).

`tests/test_bip340.py` checks that reference in both directions: it reproduces the 8 published signatures
byte for byte and rejects the 10 malformed inputs, matches all 7 BIP341 tweak vectors and the 3 BIP86 key
pairs. It also pins the two facts the applet's taproot code depends on, and which are easy to get subtly
wrong: an empty merkle root and 32 zero bytes are *different* tweaks (only the former is BIP86), and the
pre-0.16 applet's XOR tweak agrees with BIP341 exactly when the merkle root is all-zero.

That reference is what the on-card taproot tests compare the card against, so run this suite first: if it
fails, the hardware results below mean nothing.

### Hardware tests

The tests in the repository root are separate, need a card in a reader (ideally a non-initialized one) and
are not part of `run_all.py`:

| File | Covers |
|---|---|
| `test_satochip.py` | BIP32 key derivation against the BIP32 test vectors, message signing, 2FA |
| `test_satochip_taproot.py` | The applet's `TaprootTweakPrivateKey()` and `SignSchnorrHash()` |
| `test_satochip_musig2.py` | The applet's `Musig2GenerateNonce()` and `Musig2SignHash()`, against the BIP327 test vectors |
| `test_seedkeeper.py` | The SeedKeeper applet |

```
python -m unittest -v test_satochip.py
python -m unittest -v test_satochip_taproot.py
python -m unittest -v test_seedkeeper.py
```

**Warning:** these are destructive. They import and reset the BIP32 seed, import and reset private keys in
the key slots, and expect the PIN to be `123456`. Only run them against a development card, never against
a card holding funds.

`test_satochip_musig2.py` additionally requires a debug build of the applet (branch `musig2-debug-test`),
which hardcodes the randomness of the BIP327 vectors and disables secnonce encryption. That build is for
testing only and must never be used in production.

`test_satochip_taproot.py` needs no debug build. `SignSchnorrHash()` draws its BIP340 `aux_rand` on-card,
so its signatures are not reproducible and cannot be compared to a vector byte for byte — but they do not
need to be, since a schnorr signature is checked by *verifying* it against the public key. The BIP341
tweak, which is deterministic, is compared value by value. The suite covers both tweak forms (a 32-byte
merkle root and `tweak_size=0`), the keyslot and BIP32 key sources, BIP86 derivation end to end from the
seed, the bypass (Nostr) path, the authentikey signature over the returned pubkey, nonce freshness across
repeated signatures, that a signature does not verify under the untweaked key, the schnorr feature policy,
and the input-validation status words. It skips itself cleanly when no reader, no card, or a 2FA-enabled
card is present.

## Development version (Windows)

Install the latest python 3.6 release from https://www.python.org (https://www.python.org/downloads/release/python-368/)
(Caution: installing another release than 3.6 may cause incompatibility issues with pyscard)

Clone or download the code from GitHub.
    
Install pyscard from https://pyscard.sourceforge.io/
Pyscard is required to connect to the smartcard::

    python -m pip install pyscard
    
In case of error message, you may also install pyscard from the installer:
Download the .whl files from https://sourceforge.net/projects/pyscard/files/pyscard/pyscard%201.9.7/ and run::

    python -m pip install pyscard-1.9.7-cp36-cp36m-win_amd64.whl

## Development version (Ubuntu)

Check out the code from GitHub::
    
    git clone git://github.com/Toporin/pysatochip.git
    cd pysatochip
    
Install pyscard (https://pyscard.sourceforge.io/)
Pyscard is required to connect to the smartcard:: 
    sudo apt-get install pcscd
    sudo apt-get install python3-pyscard
(For alternatives, see https://github.com/LudovicRousseau/pyscard/blob/master/INSTALL.md for more detailed installation instructions)
