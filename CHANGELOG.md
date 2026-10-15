# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.18.5]:

Security: do not leak secrets through logs or stdout; harden the secure-channel AES

Three paths could expose key material on the host, independently of the card.

`satochip_import_privkey()` ended with a `print()` of the command APDU, which embeds the raw
32-byte private key; being a `print()` rather than a log call, no log level suppressed it.
Eleven further `print()` calls in the MuSig2 and Satocash paths dumped nonces, the encrypted
secnonce and signatures. All twelve are removed, and the status words are logged at DEBUG.

The BIP32 extended *private* key was logged at INFO by `card_bip32_get_xpub()`, and the CLI
logged the masterseed/mnemonic blob from a SeedKeeper export at INFO. Both are removed.

APDU logging masked the body of a fixed list of instructions and logged everything else in
full. That list omitted `INS_IMPORT_KEY` and the SeedKeeper import/export instructions,
existed in two diverged copies, and covered only the command direction, so decrypted responses
carrying exported masterseeds, Satodime private keys or `xprv` were logged verbatim at DEBUG.
Both directions now use one `_redact_apdu()`/`_redact_response()` pair driven by an allow-list,
`_LOGGABLE_INS`: the body is rendered only for instructions known to carry no secret, and
anything else, including an unclassified instruction, shows the 5-byte header with the body
masked.

Three remaining correctness bugs.

`card_bip32_get_xpub()` and `card_bip32_get_xprv()` document `path` as `str | bytes`, but only
the `str` branch bound `depth` and `bytepath`, so passing bytes raised `UnboundLocalError` on
the very next line. A bytes path now derives the same values directly, and a `bytearray` or a
list of ints works too.

`Satochip2FA.do_challenge_response()` used `continue` in its exception handler, which skipped
both the `time.sleep(period)` and the `timeout -= period` below it. An unreachable 2FA server
therefore produced an infinite full-speed retry: the 180 second timeout never fired and the
call never returned, hanging the signing flow. It now falls through to the backoff, so the
timeout works. An empty (falsy but not `None`) reply also used to leave `reply_encrypt` unset,
raising `KeyError` in the caller; the key is now always set.

`parse_to_compact_sig()` read `sigin[4+lr-1-i]` *before* checking `lr >= (i+1)`. For `i >= lr`
the index went negative and Python wrapped it round to the end of the buffer, so it quietly
read unrelated bytes and would raise `IndexError` once it passed `-len(sigin)`. The value was
discarded in that branch, which is why it never surfaced. Both the r and s loops now index only
once the guard has passed.

Four defects that made a failure look like something else.

`get_sw12()` returned `16*sw1+sw2`, interleaving the nibbles: `(0x9C, 0x01)` came out as
`0x9C1` rather than `0x9C01`, so a comparison against any `JCconstants.SW_*` value could never
match. It is public API; every other site in the file open-codes `256*sw1+sw2`, which is why
this went unnoticed.

`card_reset_factory_v3()` raised `UnexpectedSW12Error` with `sw1` passed twice, so callers
inspecting `ex.sw2` saw a copy of `sw1`.

`card_change_PIN()` had no catch-all branch. On any status other than success, wrong PIN or
blocked PIN it returned normally while `self.pin` still held the old value, so a caller that
did not re-check `sw1`/`sw2` believed the PIN had been changed. It now raises, and the cached
PIN is left untouched.

`card_import_trusted_pubkey()` and `card_export_trusted_pubkey()` handled a few specific
statuses and then fell through to the parser with whatever the card had returned, without ever
asserting `0x9000`. Both now reject an unexpected status before parsing; the documented
special cases of the export command (`0x9C35` and `0x6D00`) are unchanged.

Two APDU-construction bugs in `card_bip32_get_extendedkey()`.

The coordy length was encoded as `[len & 0xFF00, len & 0x00FF]`, masking the high byte instead
of shifting it, so any length of 256 or more would put a value above 255 into a byte list. It
is harmless today only because coordy is always 32 bytes; it now shifts, at both of the two
places that built this field.

The out-of-memory retry did `apdu[3] = apdu[3] ^ 0x80`, which *toggles* the erase flag rather
than setting it: a caller that had already set bit 7 had it cleared instead, so the retry asked
the card not to erase. The following `apdu[3] &= 0x7f` then cleared bit 7 unconditionally,
discarding a flag the caller had explicitly passed. The retry now sets the flag and restores
the caller's original value.

The `while (True)` wrapping that exchange has also been removed: every branch inside it returns
or raises, so it never looped.

Two pieces of card state were recorded in the wrong place.

`satocash_get_status()` wrote the Satocash "PIN required" flag into `self.is_seeded`, the
Satochip "a BIP32 seed is loaded" flag, so reading the status of a Satocash clobbered an
unrelated piece of state with it. `CardConnector.__init__` already declares `self.needsPIN`
for this, and that is where it now goes.

`satodime_set_unlock_secret()` set `self.is_owner = False` when called with no secret and then
immediately overwrote it with an unconditional `self.is_owner = True`. A client that had no
unlock secret therefore believed it was the owner of the Satodime while every unlock code it
computed was keyed with the all-zero placeholder. Ownership now follows the secret, and is
dropped again if the secret is cleared.

The CLI now asks Click which command was invoked instead of reading `sys.argv[1]`. That is the
first *argument*, not the command, so any global option in front of it was mistaken for the
command: `satochip-cli --verbose util-generate-local-keypair` inferred no device filter and
then opened the card and established a secure channel for a util- command that needs neither.
`ctx.invoked_subcommand` is also resolved through `AliasedGroup`, so abbreviated command names
now infer the device filter correctly as well.

Two Satocash CLI bugs made it report, and act on, wrong proof data. Both were silent: the
output looked plausible either way.

`keyset_indexes_by_mint = max_nb_mints * [set()]` put the *same* set object at every index, so
adding a keyset to one mint added it to all of them. That list is handed to
`satocash_export_keysets()`, so `satocash-export-tokenv4` selected proofs belonging to other
mints. The neighbouring `max_nb_mints * [0]` lines are fine only because integers are immutable
and `+=` rebinds rather than mutates, which is what makes the bug easy to miss. Both set lists
are now built with a comprehension.

`satocash-get-proof-info` decoded the proof state with `value ^ 0x03` while the comment on the
same line said "MASK 0x03". XOR reported unspent proofs as spent and spent ones as unspent, and
turned every P2PK-flagged proof and every empty slot into "UNKNOWN". It now masks, as the
adjacent `value & 0x80` check already did.

Three CLI commands were invoking other commands as if they were plain functions.
`@main.command()` binds the name to a `click.Command`, so calling it runs Click's standalone
`main()`: it re-parses `sys.argv`, re-prompts for the PIN and then exits the process.
`common-initial-setup --label X` therefore exited at the point where it set the label, and
`satodime-ownership-claim` passed `--satodime`, which `common_initial_setup` does not accept,
so Click aborted with a usage error before anything ran -- that command never worked. The
shared bodies are now plain `set_card_label()` and `initial_setup()` helpers that both the
commands and the internal callers use; the commands themselves and their options are unchanged.

Key material returned by the card is now signature-checked.
`card_bip32_get_liquid_master_blinding_key()` parsed the signature and then left a
`# todo verify signature` where the check belonged, returning the SLIP-77 master blinding key
unverified -- a hostile or swapped card chose the blinding key for every confidential Liquid
address derived from it. `satocash_get_bip32_extendedkey()` had the same `# todo` and
additionally rebuilt the compressed pubkey from the card's claimed uncompressed point without
checking it is on the curve, so only the x coordinate survived and a bad y went unnoticed.

The signed message was taken from the applet sources rather than inferred: both applets sign
everything written before the signature's own length field. For the blinding key that is
`[keySize(2b) | blindingKey]`; for the Satocash response the authentikey signature covers the
counter, the pubkey and the preceding self-signature, the same construction the secure-channel
handshake already uses. Both commands now reject a missing signature and verify against the
authentikey, and the Satocash pubkey is validated as an on-curve point before being compressed.

Note that INS 0x6D is not implemented by any released Satocash applet, so
`satocash_get_bip32_extendedkey()` could not be exercised against hardware; its layout follows
the convention used everywhere else in both applets and should be confirmed on a card once the
applet implements the command.

Responses are no longer parsed before their status word is checked.
`card_initiate_secure_channel()` discarded `sw1`/`sw2` and handed the body straight to the
parser; on an error status that body is an error payload or empty, and on a body shaped like a
valid answer the session key was derived from it. With a card returning `0x6D00` and a
self-signed rogue ephemeral key in the body, the pre-0.18.5 code established a fully usable
secure channel keyed to that rogue key. It now raises `UnexpectedSW12Error` before parsing, and
`self.sc` stays `None` so no later command can use a half-built channel.

`satodime_get_pubkey()` had the same shape and now returns `(response, sw1, sw2, [], [])`
without parsing, matching `satodime_seal_key()`, `satodime_unseal_key()` and
`satodime_get_privkey()` -- it was the only one of the four missing the check. The five-value
tuple is kept, since the CLI unpacks it directly.

`card_bip32_set_authentikey_pubkey()` never looked at its result at all. That command only
caches the authentikey coordy on the chip as an optimization, and the authentikey it returns
was parsed and signature-checked from the caller's response rather than from this command, so a
failure costs performance rather than correctness -- and older applets may not implement ins
0x75. It now logs a warning instead of passing the failure over in silence, and deliberately
does not raise.

A SeedKeeper fingerprint mismatch is now an error. The card stores
`sha256(secret)[0:8]` beside each secret for exactly one purpose: to detect that the bytes on
the card are not the bytes that were meant to be there. Both `seedkeeper_import_secret()` and
`seedkeeper_export_secret()` compared it and only wrote `logger.error()` on mismatch, then
returned normally -- so a masterseed the card had stored incorrectly, or an export corrupted
or tampered with in transit, reached the caller looking exactly like a good one. For a seed
that means funds derived from it are unrecoverable.

Both now raise `SeedKeeperError`. The import error names the id the suspect secret was stored
under, since the import has already happened and the caller needs to be able to delete it. The
export check remains limited to plain exports: a secure export returns the secret encrypted to
the destination device, so the host cannot recompute the digest.

SeedKeeper export signatures are no longer skippable by the card. `seedkeeper_export_secret()`
and `seedkeeper_derive_master_password()` chose whether to verify the response signature based
on `sign_size`, a length the card chooses. A 20-byte value is legitimate -- but only for a
*secure* export, where it is an hmac keyed with the secret shared with the destination device,
which only that device can check. For a plain export the card must sign with its authentikey,
so a card that simply returned 20 bytes bypassed verification and the host stored the result as
a trusted secret. The branch now follows `is_secure_export`, which the host decides: a plain
export must carry a verifiable authentikey signature, and a secure export must carry exactly 20
bytes, any other length raising `SeedKeeperError`.

`seedkeeper_derive_master_password()` additionally caught a failed verification, put the
message in `dic['error_msg']` and returned the derived master password anyway, so a caller that
did not inspect that extra key accepted an unverified result. It now always verifies -- secure
export is unsupported there, so the hmac branch was unreachable in a legitimate flow -- and
lets the failure propagate. Because the failure had always been swallowed, it had also gone
unnoticed that the function never initialised the authentikey it verifies against; it now does,
like `seedkeeper_export_secret()`.

Callers that relied on `dic['error_msg']` to detect a bad signature should catch the exception
instead. Genuine signatures, and genuine 20-byte hmacs on secure exports, behave exactly as
before.

`get_trusted_pubkey()` now fails closed. It verified that the card had signed the trusted
pubkey with its authentikey, then caught the failure, logged it and returned the key anyway.
That signature is the only thing binding the key to the card, and the trusted pubkey is what a
secure SeedKeeper -> Satochip import encrypts a secret to, so anything able to alter the card
response could substitute its own key and receive the exported seed -- while
`card_import_trusted_pubkey()` reported success to the user. Two further ways to skip the
check existed in the same function: a card-chosen `sig_size` of 0 made verification raise
`IndexError`, caught by the same handler, and an unset authentikey raised `AttributeError`
from the debug line before any check ran.

A missing authentikey and an empty signature are now rejected up front, matching the
`raise ValueError("Signature missing")` pattern the other parsers already use, and a failed
verification is re-raised as a `ValueError` chained to the original cause. Both call sites in
the CLI already wrap the call, so this surfaces as an error message instead of a bogus pubkey.
Callers that previously ignored the return value's trustworthiness will now see an exception
where they used to silently receive an unverified key.

`card_parse_transaction()` is deprecated, and `TxParser` is removed. The function kept a
whole Bitcoin transaction parser alive to produce a value that never depended on the parse:
`TxParser` only accumulated the bytes it walked over, so `get_tx_double_hash()` was always the
plain double-sha256 of its input, on both the legacy and the segwit code path. That was
verified over 500 generated transactions -- multi-input, multi-output, and with scripts
straddling the parser's 128-byte chunk size and the 0xfd varint boundary -- before the parser
was deleted.

It now computes `sha256d(transaction)` directly. `is_segwit` is accepted and ignored, since it
only ever selected a parsing path. The signature and the `(response, sw1, sw2, tx_hash,
needs_2fa)` return contract are unchanged, so existing callers such as Electrum keep working;
the function emits a `DeprecationWarning` and the docstring states that it does not parse its
input. New code should call `pysatochip.util.sha256d()` and
`card_sign_transaction_hash()` instead.

Dropping the parser also removes a denial of service. `TxParser.parse_byte()` sliced without
bounds checks, and Python slicing does not raise on over-read, so a truncated or malformed
transaction drove its remaining-byte counter negative and `is_parsed()` never became true
again; the caller was an unguarded `while not txparser.is_parsed()` spin loop. A corrupt or
hostile transaction could therefore wedge the process at 100% CPU. The parser also called an
undefined `read_int32()` for any varint in the 0xFE form, raising `NameError` on transactions
with scripts of 65536 bytes or more. Hashing cannot fail that way, and the new tests cover
empty, truncated and arbitrary input. `CardDataParser.parse_parse_transaction()`, dead since
the ins 0x71 ParseTransaction command was removed in applet v0.16-0.0, is deleted too.

Logging configuration now belongs to the application. The library called
`logger.setLevel()` and `logging.basicConfig()` at import time, and every constructor applied
its `loglevel` argument to the *module* logger with a default of WARNING, so merely
constructing an object overrode whatever the host application had configured, and a second
instance retroactively changed the first. The level was also relayed by three different
mechanisms and never reached `certificate_validator`, `ec_backend`, `aes_backend` or
`TxParser`, so `--verbose` skipped them.

`pysatochip/__init__.py` now installs a `NullHandler` on the package logger and exposes
`set_log_level(level)`, which sets the level once on the `pysatochip` logger and cascades to
every submodule; module loggers stay at NOTSET so nothing blocks the cascade. The `loglevel`
constructor arguments keep their name, position and meaning, but default to `None` (leave the
application's configuration alone) and, when given, simply call `set_log_level()`.

Two observable changes for existing applications. An application that configures no logging at
all no longer sees pysatochip warnings on stderr, because the `NullHandler` replaces
`logging.lastResort`; in practice the library signals failure by raising far more than by
logging. And an application whose root logger is at DEBUG, but which never passed `loglevel`,
now gets pysatochip debug output where the library previously forced itself to WARNING;
`logging.getLogger('pysatochip').setLevel(logging.WARNING)` restores the old volume.

The secure channel no longer uses `pyaes` by default: its table-driven AES makes memory access
key-dependent, the same class of side channel that led to the removal of the `ecdsa` package
in v0.18.0 (CVE-2024-23342), here applied to the session key. The new `aes_backend` module
selects `cryptography`, then `pycryptodomex` (both already dependencies), keeping `pyaes` as a
last resort for embedded builds that ship neither. The wire format is unchanged -- AES-128-CBC
with PKCS#7, same key and IV construction -- and a vector captured from the previous `pyaes`
output pins it. Unlike `ec_backend` this does not fail closed when only `pyaes` is available,
since the secure channel is mandatory from applet v0.11; it logs a warning instead.

PKCS#7 unpadding is now validated: `pyaes` only checked that the final byte was at most 16 and
never compared the padding bytes, so a response ending in `0x00` decoded to an empty plaintext.
Malformed padding, IV length or ciphertext length now raise `SecureChannelError`, which moves
to a single definition in `SecureChannel.py` and stays re-exported from `CardConnector`.

`python_requires` moves from 3.6 to 3.9, which the code already required: a PEP 701
nested-quote f-string in the CLI was a `SyntaxError` below 3.12, breaking the `satochip-cli`
entry point rather than just that command, and `list[int]` annotations need 3.9. The f-string
is fixed. The `cryptography` minimum moves to 42.0.0, as it is the default backend for every
private-key operation and the 3.3.2 floor admitted releases with known CVEs.

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

