# AGENTS.md

Guidance for AI coding agents working on this repository. Read this before making changes.

## Project overview

**pysatochip** is a Python client library for the Satochip hardware wallet and its sibling
javacard applets (SeedKeeper, Satodime, Satocash). It talks to smartcards over PC/SC using
`pyscard`, exchanging APDUs with the on-card applet
([SatochipApplet](https://github.com/Toporin/SatochipApplet)). Downstream consumers are wallet
clients such as Electrum and Electrum forks, plus a bundled command-line tool (`satochip-cli`).

- License: LGPL v3 (some files carry Apache-2.0 or MIT-style Electrum headers; keep them intact)
- Python: >= 3.9 (per `setup.py`); developed and tested on CPython 3.12
- Package on PyPI: `pysatochip`; current version lives in `pysatochip/version.py` (0.18.5)
- Upstream: https://github.com/Toporin/pysatochip

## Repository layout

- `pysatochip/` — the library package:
  - `CardConnector.py` — the main API. The `CardConnector` class wraps card discovery
    (pyscard `CardMonitor`/observer threads), APDU transmission, PIN handling, and exposes
    all applet operations: `card_*` (Satochip), `seedkeeper_*`, `satodime_*`, `satocash_*`.
    Protocol exceptions (`WrongPinError`, `UninitializedSecureChannelError`, ...) are also
    defined here. Very large file (~4600 lines); navigate by method name.
  - `JCconstants.py` — APDU CLA/INS codes, status words (SW), capability bits. Must stay in
    sync with the applet; values are part of the wire protocol.
  - `SecureChannel.py` — the encrypted channel to the card: ECDH key exchange + key
    derivation (HMAC-SHA1) + AES-128-CBC via `aes_backend`. The wire format is pinned by
    regression vectors (see Testing).
  - `aes_backend.py` — AES backend selection for the secure channel, mirroring
    `ec_backend.py`: `cryptography`, then `pycryptodomex`, with pure-python `pyaes` only
    as a last resort for embedded builds. PKCS#7 padding lives here so every backend
    behaves identically. Unlike `ec_backend` it does not fail closed, since the secure
    channel is mandatory from applet v0.11.
  - `ec_backend.py` — side-channel-hardened EC backend. **All** secret-dependent operations
    (ECDH, signing, key derivation) must go through this module. It selects
    `pyca/cryptography` by default, or libsecp256k1 via `embit` when cryptography is absent
    (embedded builds such as seedsigner-os), and raises `NoECBackendError` if neither is
    importable.
  - `ec_math.py` — pure-python secp256k1 arithmetic for **public data only** (pubkeys,
    signatures, recovery, DER). Never pass private keys into this module.
  - `ecc.py` — public API classes `ECPubkey` / `ECPrivkey` (Electrum-derived), delegating to
    `ec_backend`/`ec_math`.
  - `certificate_validator.py` — card-authenticity certificate chain validation, using
    pyOpenSSL when available with a pure-python `pycryptodomex` fallback (`backend="auto" |
    "openssl" | "pycryptodomex"`). CA certificates ship in `pysatochip/cert/*.cert`
    (packaged via `package_data`).
  - `CardDataParser.py` — parser for APDU responses. (`TxParser.py` was removed in
    0.18.5: `card_parse_transaction()` is deprecated and now just double-sha256s its
    input, which is all the parser ever produced.)
  - `Satochip2FA.py` — optional 2-Factor-Authentication (HMAC challenge/response, server list).
  - `SecretDecryption.py` — decryption of encrypted SeedKeeper JSON backups.
  - `electrum_mnemonic.py`, `slip44.py`, `util.py` — Electrum seed mnemonics, SLIP-44 coin
    constants, base58/hash helpers.
  - `version.py` — applet protocol version tuples **and** the library version
    (`PYSATOCHIP_*`). Single source of truth for versioning.
- `satochip_cli.py` (repo root) — the CLI, built with `click` (commands grouped under an
  `AliasedGroup`, registered with `@main.command()`). **This root file is the source of
  truth**: `setup.py` copies it to `pysatochip/satochip_cli.py` at build time, and the copy
  is gitignored. Never edit the copy.
- `tests/` — offline unit tests (no card needed); see Testing.
- `test_satochip.py`, `test_satochip_taproot.py`, `test_satochip_musig2.py`,
  `test_seedkeeper.py` (repo root) — hardware tests requiring a real card; see Testing.
- Docs: `README.md` (library + tests), `README-CLI.md` (CLI usage), `CHANGELOG.md`.

## Build and install

There is no `pyproject.toml`; packaging is setuptools-based:

- `setup.py` + `requirements.txt` + `MANIFEST.in`. Runtime deps: `pyscard`,
  `cryptography` (default EC and AES backend), `pyopenssl`, `pycryptodomex`, `pyaes`
  (last-resort AES only), `certifi`.
- Extras: `pip install "pysatochip[CLI]"` (mnemonic, click, websockets, nostr, cbor2) and
  `pip install "pysatochip[embedded]"` (embit/libsecp256k1 fallback backend).
- Install from source: `pip install .` / `pip install -e ".[CLI]"`, or legacy
  `python setup.py install`.
- Distribution: `python -m build` (or `setup.py sdist bdist_wheel`) produces wheel + sdist
  in `dist/`; published to PyPI. `MANIFEST.in` grafts the package and includes
  README/CHANGELOG/LICENSE/requirements.
- The console entry point is `satochip-cli=pysatochip.satochip_cli:main`; from a checkout
  you can also run `python satochip_cli.py`.
- Running anything against a real card needs the PC/SC daemon (`pcscd` on Linux) and pyscard
  working; library-only work and the offline test suite do not.

## Testing

Two completely separate suites:

### Offline suite (`tests/`, stdlib `unittest`, no hardware, no pytest)

```bash
python tests/run_all.py                          # runs everything, prints active EC backend
python -m unittest discover -s tests -t .        # stdlib discovery from repo root
python tests/test_ec_backend.py                  # a single file directly
python tests/test_ec_backend.py TestECDH.test_shared_secret_matches_frozen_vector
```

Key conventions:

- Tests are parametrized per available EC backend (`ec_backend.available_backends()`), so
  what runs depends on what is installed. With only `cryptography`, libsecp256k1 and
  cross-backend tests **skip themselves** (expect e.g. `OK (skipped=11)`); install
  `pysatochip[embedded]` for full coverage. Do not "fix" these skips.
- `tests/test_backend_scenarios.py` runs subprocesses with imports deliberately blocked
  (`tests/_blocker.py`) to simulate deployment environments (desktop, seedsigner-os with
  neither cryptography nor pyOpenSSL, and no-backend-at-all). The last scenario asserts that
  private-key operations **fail loudly** when no hardened backend exists — that is intended.
- `tests/vectors.py` holds golden secp256k1 vectors captured from the pre-0.18.0 `ecdsa`
  implementation. `ECDH_SHARED_X` pins the card secure-channel wire format: **if a change
  makes this vector fail, treat it as a compatibility break in your change, not a broken
  test.** `tests/_gen_vectors.py` documents how they were produced and refuses to run on the
  current tree.
- `tests/test_bip340.py` pins `tests/bip340_ref.py` (a pure-python BIP340/BIP341 reference
  built on `ec_math.py`) against the official BIP340/BIP341/BIP86 vectors in
  `tests/vectors_bip340.py`. The hardware taproot tests compare the card against this
  reference, so it must pass before any hardware result is meaningful. Note the pinned
  subtlety: an empty merkle root (`tweak_size=0`) and 32 zero bytes are *different* tweaks;
  only the former is BIP86.

### Hardware suite (repo root, needs a card — destructive!)

`test_satochip.py`, `test_satochip_taproot.py`, `test_satochip_musig2.py`,
`test_seedkeeper.py` are run individually, e.g. `python -m unittest -v test_satochip.py`.
They reset the BIP32 seed and key slots and expect PIN `123456`. **Never run them against a
card holding funds** — use a development card only. `test_satochip_musig2.py` additionally
needs a debug applet build (`musig2-debug-test` branch) that must never be used in
production. These suites are deliberately excluded from `tests/run_all.py`.

## Code conventions

- English for all code, comments and docs.
- Standard library `logging`: each module does `logger = logging.getLogger(__name__)`,
  giving the hierarchy `pysatochip.<module>`. Module loggers **must stay at NOTSET**
  — never call `logger.setLevel()` at import time or from a constructor, and never
  add a handler or call `logging.basicConfig()` outside a `__main__` block. Level and
  handler policy belong to the application that imports the library; a module logger
  with its own level also blocks the cascade described next.
  `pysatochip/__init__.py` installs a `NullHandler` on the package logger and exposes
  `set_log_level(level)`, which sets the level once on `pysatochip` and therefore
  cascades to every submodule. Classes still accept a `loglevel` constructor argument
  for backward compatibility, but it defaults to `None` (do nothing) and, when given,
  is just a call to `set_log_level()` — it is package-wide, not per-instance.
- Never log secret material. APDU logging goes through `_redact_apdu()` /
  `_redact_response()` in `CardConnector.py`, which mask the body unless the
  instruction is on the `_LOGGABLE_INS` allow-list. The list is deny-by-default on
  purpose: a new secret-bearing instruction stays masked until someone clears it.
  Library modules must not `print()` at all. See CHANGELOG 0.18.5.
- APDU-level methods in `CardConnector` follow the `<applet>_<action>` naming pattern and
  return parsed values or raise the dedicated exceptions defined at the top of
  `CardConnector.py`; card status words are checked against `JCconstants` rather than magic
  numbers.
- Type hints are present but partial (`typing.Union/Optional/List`); match the style of the
  surrounding code rather than retrofitting.
- Byte-oriented API: keys and signatures cross module boundaries as `bytes`
  (see the `ec_backend.py` docstring). No backend objects leak to callers.
- Threading matters: pyscard observers run in monitor threads while client code runs in the
  caller's thread. The secure channel is established lazily by whichever thread needs it
  first (`card_ensure_secure_channel()`, idempotent and lock-protected); `self.sc` is only
  ever `None` or a fully usable channel. Preserve these invariants when touching connection
  code (see CHANGELOG 0.18.1 for the race this fixed).
- Comments that explain *why* (security rationale, protocol constraints) are valued in this
  codebase; keep docstrings accurate when changing behavior.

## Security considerations

- **CVE-2024-23342 ("Minerva")**: the pure-python `ecdsa` package was removed in v0.18.0
  because its scalar multiplication is not constant time. Do not reintroduce it (or any
  non-hardened implementation) for private-key operations. Secret-dependent math belongs in
  `ec_backend.py`; `ec_math.py` is for public data only. See issue #8.
- Never weaken the "fail loudly" behavior: when no hardened backend is importable, signing
  and ECDH must raise `NoECBackendError`, never fall back to something vulnerable.
- The secure-channel ECDH wire format is frozen by `tests/vectors.py::ECDH_SHARED_X`; the
  applet derives the same secret on-card, so changing it breaks every Satochip/SeedKeeper/
  Satodime session in the field.
- Taproot: `card_taproot_tweak_privkey()` must distinguish `tweak=None` (key-path-only BIP86
  tweak, `tweak_size=0`) from a 32-byte merkle root; padding a missing tweak with zero bytes
  produces a valid-looking but non-BIP341 key whose coins standard wallets cannot spend
  (fixed in 0.18.2 — do not regress).
- Hardware tests and CLI commands can reset seeds, keys and PINs. Default test PIN is
  `123456`. Never suggest running them on a production card.
- Test vectors contain private keys — they are test-only values and must stay clearly marked
  as such; never use them on a real device.
- Certificate validation defaults to OpenSSL and falls back to pycryptodomex; both legs are
  tested against the shipped CA certs in `pysatochip/cert/`.

## Release process

1. Bump `PYSATOCHIP_MAJOR/MINOR/REVISION` in `pysatochip/version.py` (it also documents the
   applet protocol versions; keep the comment history style).
2. Add a `CHANGELOG.md` entry — Keep a Changelog format, SemVer, one `## [x.y.z]:` section
   per release with a prose explanation of the *why*.
3. Build sdist + wheel into `dist/`, publish to PyPI as `pysatochip`.

There is no CI configuration in this repository; run `python tests/run_all.py` (and the
relevant hardware suite if you touched APDU-level code) before considering work done.
