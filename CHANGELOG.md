# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.18.6]:

**Packaging: fix the contents of the source distribution**

### Fixes
- The repo-root `satochip_cli.py` — the CLI's single source of truth, which `setup.py` copies into the package at build time to back the `satochip-cli` console script — was not included in the sdist. Building pysatochip from the sdist (e.g. `pip install --no-binary :all:`, as done by deterministic binary builds) therefore crashed in `setup.py` with `FileNotFoundError: 'satochip_cli.py'`. The file is now shipped via `MANIFEST.in`; the build-time copy mechanism, the console entry point and the CLI itself are unchanged.
- The sdist also carried the build machine's compiled bytecode: `graft pysatochip` in `MANIFEST.in` swept the whole package directory, `__pycache__/` included, so every release since 0.17.0 shipped ~500 KB of CPython-version-specific `.pyc` files — among them a stale `TxParser.cpython-312.pyc`, bytecode for a module removed in 0.18.5. Harmless at import time, since Python only consults a `.pyc` when importing its matching `.py`, but opaque binaries have no place in an artifact that is meant to be auditable source, and they made the tarball non-reproducible. `MANIFEST.in` now excludes `*.py[cod]` and `__pycache__`, halving the sdist. Wheels were never affected: `bdist_wheel` builds from `find_packages()` rather than from `MANIFEST.in`.

## [0.18.5]:

**Security: stop leaking secrets through logs and stdout; harden secure-channel AES**

### Security
- **Secrets no longer printed or logged.** Removed 12 `print()` calls, including the one in `satochip_import_privkey()` that dumped the raw private key. The xprv is no longer logged in `card_bip32_get_xpub()`, and the CLI no longer logs SeedKeeper masterseeds or mnemonics.
- **APDU logging uses an allow-list (`_LOGGABLE_INS`)** for both commands and responses. Bodies of unlisted instructions are masked. Previously, `INS_IMPORT_KEY`, SeedKeeper import/export and all decrypted responses were logged in full at DEBUG.
- **Secure channel checks the status word before parsing.** A card returning `0x6D00` with a rogue ephemeral key could previously establish a usable channel. `self.sc` now stays `None` on failure.
- **Card-returned key material is now signature-checked.** This applies to `card_bip32_get_liquid_master_blinding_key()` and `satocash_get_bip32_extendedkey()`, where the pubkey is also checked to be on the curve. INS 0x6D is not yet implemented by any Satocash applet, so the latter is untested on hardware.
- **SeedKeeper:**
  - A fingerprint mismatch on import or export now raises `SeedKeeperError` instead of only logging. The import error names the stored id.
  - Whether the signature is verified now depends on `is_secure_export`, not the card-chosen `sign_size`. A card can no longer skip verification by returning 20 bytes.
  - `seedkeeper_derive_master_password()` always verifies and raises on failure. It also now initialises its authentikey.
- **`get_trusted_pubkey()` fails closed.** A missing authentikey, an empty signature or a failed verification now raises `ValueError`. Previously the key was returned unverified.
- **AES backend:** the secure channel now uses `cryptography`, then `pycryptodomex`, and falls back to `pyaes` with a warning. This avoids `pyaes`'s key-dependent table lookups. The wire format is unchanged. PKCS#7 padding, IV and ciphertext lengths are now validated and raise `SecureChannelError`.

### Fixes
- `base_encode(base=43)` raised `NameError`. The alphabet is now defined, matching Electrum.
- `card_bip32_get_xpub()`/`get_xprv()` now accept bytes, `bytearray` or a list of ints as `path`.
- `Satochip2FA.do_challenge_response()` retried forever at full speed when the server was unreachable. The backoff and timeout now work, and `reply_encrypt` is always set.
- `parse_to_compact_sig()` no longer reads at negative indices.
- `get_sw12()` returned `16*sw1+sw2` instead of `256*sw1+sw2`.
- `card_reset_factory_v3()` passed `sw1` twice to `UnexpectedSW12Error`.
- `card_change_PIN()` now raises on any unexpected status.
- `card_import/export_trusted_pubkey()` now reject unexpected statuses before parsing.
- `card_bip32_get_extendedkey()` had two bugs. The coordy length masked the high byte instead of shifting it. The out-of-memory retry toggled the erase flag instead of setting it. A dead `while True` loop was also removed.
- `satocash_get_status()` now writes `needsPIN` instead of overwriting `is_seeded`.
- `satodime_set_unlock_secret()` now only claims ownership when a secret is set.
- `satodime_get_pubkey()` checks the status word before parsing.
- `card_bip32_set_authentikey_pubkey()` logs a warning on failure.
- `card_transmit()` recovers when the card loses the secure-channel session (applet deselected, card reset or reader power-off during an idle period). It re-initiates the channel and retries the command once on the whole `0x9C20`-`0x9C23` family, not just `0x9C21`: old applets keep the "initialized" flag persistent while the session keys live in transient memory, so a reset surfaced as `0x9C22`/`0x9C23` and failed the command. The retry is bounded on purpose — a persistent `0x9C22`/`0x9C23` can indicate tampering on the PC/SC path. `card_verify_PIN_simple()` got the same treatment.
- **CLI:**
  - The command is now detected with `ctx.invoked_subcommand` instead of `sys.argv[1]`. Global options and abbreviated names now work.
  - A shared-`set()` bug made `satocash-export-tokenv4` select proofs from other mints.
  - `satocash-get-proof-info` decoded proof state with XOR instead of a mask.
  - Commands calling other commands exited the process early. `common-initial-setup --label` exited at the label step, and `satodime-ownership-claim` never worked.

### Minor
Normalise all text files to LF. Whitespace only: this commit changes no content. 
9 of 68 tracked files were not pure LF. .gitattributes now makes this a property of the repository rather than of each
contributor's core.autocrlf, which is invisible and does not fix anything retroactively.

### Changes
- **`card_parse_transaction()` is deprecated** and now returns `sha256d(transaction)` directly. The return contract is unchanged. `TxParser`, which could hang at 100% CPU on malformed input, is removed, along with the dead `parse_parse_transaction()`. New code should use `util.sha256d()` with `card_sign_transaction_hash()`.
- **Logging belongs to the application.** The package installs a `NullHandler` and exposes `set_log_level()`. `loglevel` constructor arguments default to `None` and no longer override the host's configuration.
- `python_requires >= 3.9`. A nested-quote f-string that broke the CLI below 3.12 is fixed. The minimum `cryptography` version is now 42.0.0.

### Upgrade notes
- **Several silent failures now raise:** SeedKeeper fingerprint and signature checks, `get_trusted_pubkey()`, `card_change_PIN()`, trusted-pubkey import/export and secure-channel setup. Callers checking `dic['error_msg']` should catch the exception instead.
- **Logging output changes:**
  - Applications without logging configured no longer see pysatochip warnings on stderr.
  - Applications whose root logger is at DEBUG now get pysatochip debug output.
  - To restore the old behaviour, call `logging.getLogger('pysatochip').setLevel(logging.WARNING)`.

## [0.18.4]:

Fix: restore the derived keys when the card has lost them (applet v0.16-0.0)

Since applet v0.16-0.0, the BIP32 extended key (keynbr 0xFF) and the taproot tweaked key are
transient: the card clears them on deselect and card reset, for instance when another
application selects another applet through the same reader. `card_transmit()` already hides
such a reset: it opens a new secure channel (0x9C21) and verifies the cached PIN (0x9C06),
then resends the command. With older applets, which kept the keys in flash, the command then
succeeded with the key derived in the previous session; with v0.16-0.0 it fails with
SW_INCORRECT_INITIALIZATION (0x9C13).

`card_sign_transaction_hash()` (hence `card_sign_message()` and `card_sign_transaction()`)
and `card_taproot_tweak_privkey()` with keynbr 0xFF, and `card_sign_schnorr_hash()`, now
replay the last derivation (and the last tweak for schnorr) made through the CardConnector
when the card returns 0x9C13, then resend the command once. The replay is only accepted if
the card returns the same public key (and chaincode) as the first time: a key is never
restored on another card or from another seed. Otherwise, the 0x9C13 status is returned to
the caller as before, with a log message: the key must be derived again in the same card
session. Both keys are restored together, so the BIP32 key derived last is still the one used
with keynbr 0xFF after a schnorr signature.

Clients that derive the key just before signing (Electrum-Satochip, satochip-cli) are not
otherwise affected. MuSig2 is not covered: the card keeps the encrypted secnonce sent by
`card_musig2_sign_hash()` in a buffer cleared on deselect too, so the whole signature must be
restarted after a reset. Offline tests: `tests/test_derived_key_recovery.py`.

## [0.18.3]:

Change: message and transaction signing now use SignTransactionHash (ins 0x7A)

Applet v0.16-0.0 removes the ParseTransaction (0x71), SignTransaction (0x6F) and SignMessage
(0x6E) commands -- they now return SW_INS_DEPRECATED (0x9C26). The hashing these commands
performed on-card is now done client-side, and the resulting hash is signed with the
SignTransactionHash command (0x7A). Since 0x7A has existed since applet v0.10 and the card
used to sign sha256(preimage) -- exactly the double hash now sent to it -- the signatures
are the same and behavior is identical on older applets:

* `card_sign_message()` computes `sha256d(msg_magic(message, altcoin))` itself and signs it
  with a single APDU instead of the chunked INIT/PROCESS/FINALIZE flow; the compact
  signature recovery is unchanged.
* `card_parse_transaction()` no longer exchanges APDUs: it hashes the (prepared) transaction
  locally with `TxParser` -- the same double-sha256 of the sighash preimage (legacy, or
  BIP143 for segwit) that the card used to compute -- and returns it with `needs_2fa` (now
  simply whether 2FA is enabled). The return-tuple contract is unchanged, so callers such as
  Electrum need no modification. Note that the card can no longer attest the hash with its
  authentikey: the client is solely responsible for building the correct preimage.
* `card_sign_transaction()` delegates to `card_sign_transaction_hash()`.

Two 2FA challenge formats change as a consequence (the library only relays the hmac; the 2FA
app/server must be updated):

* message signing: hmac-sha1 of `[sha256d(msg_magic) | 32-byte 0xCC-padding]` (was a single
  sha256 with 0xBB-padding);
* transaction signing: hmac-sha1 of `[txhash | 32-byte 0xCC-padding]` (was 0x00-padding).

Also, the 2FA amount-limit exemption disappears: SignTransactionHash always requires the hmac
when 2FA is enabled (the on-card amount accounting was removed with ParseTransaction).
The 2FA test in `test_satochip.py` builds the new message-signing challenge accordingly, and
the deprecated INS constants are kept, marked as such, in `JCconstants.py`.

Change: `card_unblock_PIN()` supports the new UnblockPIN format of Satochip applet v0.16-0.0

Satochip applet v0.16-0.0 changed the UnblockPIN command (0x46) in a backward-incompatible
way: the PUK is now prefixed with its size and a new PIN can optionally be set in the same
command (`data = [PUK_size(1b) | PUK | (optional) PIN_size(1b) | (optional) PIN]`, previously
just `[PUK]`). `card_unblock_PIN()` picks the format based on the card type and the cached
protocol version -- calling `card_get_status()` first when the version is not cached yet.
The new format is only used for Satochip v0.16-0.0 and above; older Satochip versions and
the SeedKeeper, Satodime and Satocash applets keep the legacy format. The optional new PIN
is exposed through a new `new_pin` parameter (rejected with ValueError on cards that do not
support it).

Feat: `card_reset_factory_v3()` resets a Satochip v0.16-0.0+ card to factory with a single APDU

The applet replaced the legacy reset-to-factory procedure (power-cycling the card a fixed
number of times with a specific APDU in between) with a single command (ins 0xFD, p1 0xAA,
p2 0x55) that also restores the PIN/PUK try counters, so the card can be set up again
afterwards. The new `card_reset_factory_v3()` sends it, and the CLI's `common-reset-factory`
uses it for Satochip v0.16-0.0 and above (the older Satochip procedure and the
SeedKeeper/Satocash one were renamed v1/v2 for clarity).

Misc:

* CLI: `common-verify-authenticity` and `common-export-perso-certificate` no longer abort
  when setup is not done: Satochip v0.16+ does not require the PIN to check authenticity or
  export the personalization certificate.
* README now documents the schnorr/taproot test suites (offline `tests/test_bip340.py` and
  the four hardware suites, including the destructive-operation warnings).
* Added `AGENTS.md`, guidance for AI coding agents working on this repository.

## [0.18.2]:

Fix: `card_taproot_tweak_privkey()` could not request a key-path-only (BIP86) tweak

BIP341 computes the taproot tweak as `t = tagged_hash("TapTweak", x(P) || h)`, over the **concatenation** of
the internal key and the merkle root `h`. When the output commits to no script tree -- key-path-only
spending, as in BIP86 -- `h` is the *empty* byte string and only 32 bytes are hashed. Applet v0.16-0.0
expresses that as `tweak_size = 0`.

`card_taproot_tweak_privkey()` padded a missing tweak to 32 zero bytes and rejected anything that was not
exactly 32 bytes long, so it could not send `tweak_size = 0`. Hashing `x(P) || 32 zero bytes` is a different
tweak: it yields a valid-looking key that is not the BIP86 output key, whose address no standard wallet
watches and whose coins no standard signer can spend. `satochip_cli.py satochip-sign-schnorr-hash`, which
passes `tweak=None`, was therefore signing under a non-BIP341 key on a v0.16 card.

`tweak` now accepts `None`/empty for "no script tree" (and is optional, defaulting to `None`), keeps
accepting 32 bytes for a merkle root, and rejects any other length. Note that `tweak=None` and
`tweak=32*[0]` are two different tweaks; only the former is BIP86.

This only affects applet v0.16-0.0 and later. Earlier versions computed a non-BIP341 tweak from the XOR of
`x(P)` and `h`, which coincides with the BIP86 tweak exactly when `h` is all-zero -- so the keys derived by
the old client on an old applet are the same ones the new client derives on a new applet, and remain
spendable.

Also adds a test suite for the schnorr/taproot support, in two layers:
* `tests/test_bip340.py` (offline): pins `tests/bip340_ref.py`, a pure-python BIP340/BIP341 reference built
  on `ec_math.py`, to the official BIP340, BIP341 and BIP86 vectors (`tests/vectors_bip340.py`).
* `test_satochip_taproot.py` (needs a card): compares the applet's `TaprootTweakPrivateKey()` and
  `SignSchnorrHash()` to that reference, covering both tweak shapes, the bypass (Nostr) path, the BIP86
  derivation end to end, nonce freshness and the input-validation status words.

## [0.18.1]:

Fix: secure channel initialization race

Setting up a card that was not initialized yet failed with `UninitializedSecureChannelError`, raised from
`card_encrypt_secure_channel` on the first `card_setup()` call.

The secure channel used to be established by the card insertion observer, which runs in the pyscard
`CardMonitor` thread, while client code ran concurrently after a fixed `time.sleep(1)` that is not long
enough on a slow reader. `card_initiate_secure_channel()` also assigned `self.sc` *before* the 0x81
exchange, so for the duration of that round trip `self.sc` was a channel that existed but was not
initialized -- exactly the state the client thread observed. Clients reaching `card_setup()` first never
initiated the channel themselves either, while `card_get_status()` had already set `needs_secure_channel`.

The channel is now established lazily, by whichever thread first needs it:
* `card_encrypt_secure_channel()` calls the new idempotent, thread-safe `card_ensure_secure_channel()`.
  This is the single point where the channel is actually required, so it also covers
  `card_verify_PIN_simple()` and `card_verify_PIN_deprecated()`, which transmit directly instead of going
  through `card_transmit()`.
* `card_initiate_secure_channel()` builds the channel into a local object and publishes it to `self.sc`
  only once it is fully usable, under a lock. `self.sc` is therefore always either `None` or a working
  channel, and two threads can no longer run two 0x81 exchanges against each other. The method stays
  public and now means "force a fresh channel".
* The observer no longer initiates the channel.
* `self.sc` is invalidated in `card_disconnect()` and `card_select()`, since a new card or a re-selected
  applet resets the card side of the channel.

Callers need no change: the explicit `card_initiate_secure_channel()` calls in `satochip_cli.py` and in the
test files are now redundant but still correct. The one behaviour change is that a card whose channel
cannot be established reports the error on the first command that needs encryption, in the caller's thread,
instead of as a warning logged from the monitor thread at insertion time.

The card wire format is unchanged.

## [0.18.0]:

Security: remove the `ecdsa` dependency (https://github.com/Toporin/pysatochip/issues/8)

The pure-python `ecdsa` package is affected by CVE-2024-23342 ("Minerva"): its scalar multiplication is
not constant time, so every operation involving a private key -- ECDSA signing and ECDH key exchange --
leaks information about the secret through timing. Upstream closed the report as "not planned" and
describes the library as a teaching/testing tool rather than a production implementation, so pysatochip
no longer depends on it at all.

Private-key operations now go through a side-channel-hardened backend, selected automatically:
* `cryptography` (pyca/OpenSSL) by default. Already a pysatochip dependency, with wheels for every
  desktop platform.
* libsecp256k1 via `embit`'s ctypes binding when `cryptography` is unavailable. This covers embedded
  builds such as seedsigner-os, which ship embit (with a prebuilt libsecp256k1 for armv6l/armv7l/
  aarch64) but not cryptography. Install with `pip install pysatochip[embedded]`.

If neither backend is present, private-key operations now raise `NoECBackendError` rather than silently
falling back to a vulnerable implementation. Signature verification keeps working in that case.

Two new modules: `ec_backend.py` (backend selection and the hardened primitives) and `ec_math.py`
(pure-python secp256k1 arithmetic, signature encoding and public-key recovery -- public data only, where
constant-time execution is not a requirement and pyca/cryptography offers no recovery API).

`certificate_validator.py`'s pycryptodomex fallback no longer needs `ecdsa` either: the secp384r1
root-CA link is verified with cryptography or pycryptodomex, and the secp256k1 subCA link through
`ec_backend`.

The card wire format is unchanged -- the ECDH shared secret, secure channel key derivation and all
signature encodings are byte-identical to 0.17.4, and this is pinned by regression vectors captured from
the old implementation (`tests/vectors.py`).

Adds a `tests/` suite that runs without a smartcard (`python tests/run_all.py`), covering both backends,
the certificate chain, and the environments where one backend or the other is missing.

Behaviour change: `ECPrivkey.sign()` is no longer guaranteed to be deterministic. libsecp256k1 uses
RFC-6979 while OpenSSL uses a random nonce, so signatures stay valid, low-S and Bitcoin-compliant but are
no longer byte-identical between runs or backends. RFC-6979 is not required for validity.

## [0.17.4]: 

Feat: add pycryptodomex fallback for certificate-chain / authenticity validation

Some environments (e.g. embedded/SeedSigner-style setups) do not have OpenSSL/pyOpenSSL available, making common-verify-authenticity unusable.

certificate_validator.py now tries OpenSSL first and falls back to a pure-Python implementation using pycryptodomex + ecdsa. 
A new --backend CLI option lets callers force auto (default), openssl, or pycryptodomex.

requirements.txt adds pycryptodomex>=3.18 and README.md documents the option.

## [0.17.3]: 

Fix: correct handling of Password, Descriptor and Data secret types in seedkeeper export (https://github.com/Toporin/pysatochip/pull/9)

## [0.17.2]: 

Add support for Satodime cardNdef() command APDU
Add card_get_ndef_v2() & card_set_ndef_v2() functions:
* Check ownership for changing NDEF data
* Support 3 NDEF policies: 0: No NDEF, 1: static NDEF, 2: dynamic NDEF
* Change response format when getting current NDEF data.
* Note that APDU format is not compatible with current format used in seedkeeper applet
    
Also add CLI support, refactor a bit ApduError class and add UnsupportedFeatureError.

## [0.17.1]: 

Satocash: add NUT11 support (P2PK locked token)

The process is mostly backward compatible with previous Satocash version, and only requires an additional 4 bytes of storage per proof. 
Satocash P2PK overview:

* the client application gets a P2PK pubkey and derivation path from the card using satocash-get-bip32-extendedkey. 
A unique key is derived for each call using BIP32 derivation (the seed is generated randomly by the card).

* The client get P2PK proof from the mint locked with the given pubkey, then import the proof into the card with satocash-import-proof. 
The client must provide the nonce as 'secret' and derivation path in addition to the usual info (keyset, unblinded-key, amount). 
Note that the P2PK secret (JSON as string) is deserialized at this step (more on this later).

* To get the proof back, first the proof data is exported using satocash-export-proofs. 
This returns the nonce as 16-byte 'secret' and 'unblinded-key' data as usual. 
To recover the signature for P2PK proofs, client must additionaly call satocash-export-p2pk-sig.

* There are additional checks to ensure that only one P2PK proof can be imported as 'unspent' for each unique P2PK key: if you import multiple proofs 
locked with the same pubkey, only the fist imported proof will be marked as 'unspent' (this is to avoid offline double-spending).

There is an important caveat: for efficient storage and compatibility, the P2PK secret is not stored as a serialized string, 
but only the "nonce" and "data" (actually the derivation path) is stored in Satocash. 
The Secret string is then reconstructed by the client (POS) from the raw data after export. 
This implies to deserialize/reserialize the proof.secret JSON. 
However, this serialization is not canonical, which will be an issue if different clients (sender & receiver) serialize the secret JSON object in different ways, 
since the P2PK signature will not be valid for mismatched serialized strings. 
To avoid this issue, it would help if the NUT11 specification requires a canonical serialization for the proof.secret JSON (see [this issue](https://github.com/cashubtc/nuts/issues/278)).

Added commands:
* satocash-get-bip32-extendedkey(): Get a P2PK public key in compressed format from Satocash. 
This public key can be used to lock a proof that can only be spent by Satocash. 
A counter that represents the derivation path is also returned. This is used during proof import to tell which path is associated with the P2PK
* satocash-export-p2pk_sig(index: int): export P2PK Schnorr signature to unlock token at given index.

Modified commands api:
* satocash-import-proof(keyset_index: int, amount: int, secret: str, unblinded_key: str, p2pk_path: str): add p2pk derivation path as 8-hex counter for P2PK locked proof.
Also provide index & amount as int instead of string.

Minor command changes
* satocash-import-mint(url: str): added PIN check
* satocash-export-mint(index: int): provide index as int instead of string
* satocash-remove-mint(index: int): provide index as int instead of string
* satocash-import-keyset(keyset_id: str, mint_index: int, unit: str): provide index as int instead of string
* satocash-remove-keyset(index: int): provide index as int instead of string
* satocash-get-proof-info(unit: str, info_type: str, index_start: int, index_size: int): provide index as int instead of string
* satocash-export-tokenv4(unit: str, amount: int): provide amount as int instead of string

## [0.17.0]: 

### Satocash support

Supported commands:
* satocash_get_status(self)
* satocash_import_mint(self, url: str)
* satocash_export_mint(self, index: int)
* satocash_remove_mint(self, index: int)
* satocash_import_keyset(self, keyset_id: bytes, mint_index: int, unit: int)
* satocash_export_keysets(self, index_list: list[int])
* satocash_remove_keyset(self, index: int)
* satocash_import_proof(self, keyset_index: int, amount_exponent: int, secret_bytes: bytes, unblinded_key_bytes: bytes)
* satocash_export_proofs(self, index_list: list[int])
* satocash_get_proof_info(self, unit: int, info_type: int, index_start: int, index_size: int)

### NDEF authentikey support

PKI: add support for card_import_ndef_authentikey() APDU command
This command imports the NDEF authentikey private key into the card (if supported).
This is used to sign and authenticate NDEF record exchanged by tapping the card on a smartphone.
The NDEF authentikey may be shared by multiple devices for better privacy.

## [0.16.0]: 

### add support for MuSig2 (WIP)

* Add test class for musig2 (requires modified Satochip firmware)
* Generic CLI commands for MuSig2
* Encrypted secnonce: secnonce are exported in encrypted & authenticated format to reduce memory footprint
* Implementation using test vectors from bip327 specification
* Supported commands:
  * card_musig2_generate_nonce(self, keynbr: int, aggpk: Optional[bytes], msg: Optional[bytes], extra: Optional[bytes])
  * card_musig2_sign_hash(self, keynbr: int, secnonce: bytes, b: bytes, ea: bytes, r_has_even_y: bool, ggacc_is_1: bool)

## [0.15.5]:

* Add support for Liquid-Bitcoin Master Blinding Key export 
* Add support to Enable/disable optional features in Satochip v0.14-0.5+

## [0.15.4]:

* Add support for Nostr event signature in satochip_cli CLI.
```commandline
python3 satochip_cli.py --verbose satochip-sign-nostr-event --keyslot 0 --message "Hello, world" --kind 1 --broadcast
```

## [0.15.3]:

* Add support for Schnorr signatures:
    - sign hash with card_sign_schnorr_hash()
    - private key must be tweaked before signing using card_taproot_tweak_privkey()
* Add support for single private key wallet:
    - import a secp256k1 private key with satochip_import_privkey()
    - reset a secp256k1 private key satochip_reset_privkey()
    - recover the pubkey of a private key with satochip_get_pubkey_from_keyslot()
* Also add suport for these functions in CLI.

These functions are not yet supported when 2FA is enabled.

Some examples:
* Import a private key on slot #0:
```commandline
python3 satochip_cli.py --verbose satochip-import-privkey --keyslot 0 --privkey aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
```
* Get the corresponding publick key:
```commandline
python3 satochip_cli.py satochip-get-pubkey-from-keyslot --keyslot 0
```
* Sign a hash with Schnorr on this slot:
```commandline
python3 satochip_cli.py satochip-sign-schnorr-hash --hash 796962c8f2a7b8540f818cbe37d2894b1ab4b71bccddced12e2a4dc11d8802c3 --keyslot 0
```

More CLI commands:
* Get satochip_cli help:
```commandline
python3 satochip_cli.py
```
* Setup new card:
```commandline
python3 satochip_cli.py common-initial-setup --label my-card-label
```

## [0.15.2]:

Add NDEF support:
* get or set an NDEF tag for the card (if supported by the card)
* also add support in command line tool

## [0.15.1]:

Add support for Seedkeeper v0.2:
* add support for BIP85 derivation for Masterseed secrets stored in seedkeeper (v0.2 only)
* add support for secret export to satochip using seedkeeper_export_secret_to_satochip()
* add seedkeeper_generate_random_secret() + seedkeeper_derive_master_password() + BIP39 Mnemonic v2 
* add NFC policy support (enable/disable/deactivate)
* implement new Factory Reset mechanism for SeedKeeper v0.2
* add support for secret reset
* Update test suite for seedkeeper

CLI:
* add support to get PIN data from environment variable 'PYSATOCHIP_PIN' when available

Factory reset:
* In CardConnector, use a flag 'mode_factory_reset' to switch in and out of factory reset mode. Flag must be set to True for reset factory
* Add card_reset_factory_signal() in CardConnector to send a reset-to-factory command. Several commands must be send to reset the card, with the card must be disconnected between each command.

Porting simplified PIN method from Pysatochip v0.12.6:
* Refactor & simplify PIN verification with new method card_verify_PIN_simple(). 
* State management when PIN verification fails (wrong PIN, card removed, Pin blocked...) is handled in the client app, not in pysatochip
* Remove some exception handling in card_transmit(), usually exceptions should be handled in calling method or in client app
* Get rid of most 'self.client.request()' callbacks, except for updating status when inserting/removing card physically
* Add more specific exceptions classes

Patches:
* Add SecureChannelError Exception class
* Update status after successful setup
* Raise specific error when card not setup during PIN verification

## [0.14.3]:

 - Add CLI to access module functionality (Including code from Seedkeeper & satodime tools)
 - Fix some bugs
 - Re-Org constants a bit for less duplication
 - More doc

To use the Command Line Interface, additional dependencies need to be installed using this command: `pip install "pysatochip[CLI]"` or `pip install -e ".[CLI]"` (local install). 

## [0.14.2]:

Some minor improvements & corrections to support Satochip & Satodime.
 - Patch https://github.com/Toporin/pysatochip/issues/3
 - Satodime support: add is_owner field
 - Satodime support: add key_tokenid_int field

## [0.14.1]:

- Add support for Satodime : the open-source bearer crypto card
Website: satodime.io
Github: https://github.com/Toporin/Satodime-Applet

### Added 
 
 - Add support for Satodime
 - Add test-subca-satochip certificate (for testing only)
 
### Changed

- Refactor card_select() to choose card_applets to select
    
    A list of targeted applets is provided in CardConnector constructor through variable 'card_filter'.
    When a card is inserted, the application only attempts to select these applets.
    Selection is attempted in the order in which the applets are listed in card_filter.
    Supported applets are 'satochip', 'seedkeeper' & 'satodime'

## [0.12.3]: 

### Changed 

- Patch: allow pyscard >= v1.9.9 in requirements to solve conflicts in some (windows) build.

## [0.12.2]: 

### Added 

- Allow user to select 2FA server from a list.

## [0.12.1]: 

### Added 

- add support for SeedKeeper v0.1
SeedKeeper is a smartcard device that can be used to securely store seeds and other sensitive data for long term protection.

- add support for perso pki
During personalization, each card (Satochip and SeedKeeper) can be optionally signed and certified by a PKI.
Each card generates its own private/public keypair that is signed by the PKI, and the certificte is stored inside the card for future validation.
This is not supported by Satochip applet version<12

## [0.11.4]: 

### Added 

- add this changelog
- add new check for error code returned by the card
- add MANIFEST.in

### Changed

- change some warning message

### Fixed

- include README.md, LICENSE & CHANGELOG.md to source distributable

## [0.11.3]:

### Added 

- add support for altcoin message signing in CardConnector.card_sign_message()

## [0.11.2]: 

#### Changed

- use ecdsa & pyaes libraries instead of cryptography for ecdh key exchange

## [0.11.1]: 

### Changed

- change License to LGPLv3
- minor code changes

## [0.11.a]: 

### Added

- Pysatochip v0.11.a - Initial commit
- WIP: Integration library with support for Satochip applet up to version 0.11.

