## Command Line Interface

You can access most of Pysatochip functionality through a command line client `satochip-cli`. This can be used with _Satochip_, _Satodime_ and _Seedkeeper_.

There are a wide range of available commands, each with their own relevant options. The best way to find these is with the `--help` argument:

```commandline
python3 satochip-cli --help
```

You can have more info about a specific command by using the `--help` argument:

```commandline
python3 satochip-cli satochip-sign-message --help
```

_There are also some general tools, such as those required to decrypt encrypted Seedkeeper JSON backups. (These can be accessed either standalone or via the module)_

## installation

To install Pysatochip with the command line feature, you can use this command:

```commandline
python3 -m pip install pysatochip[CLI]
```
Or, to install from sources: 

```commandline
python3 setup.py install[CLI]
```

## Common operations

* Verify a card authenticity using default backend:
```commandline
python3 satochip_cli.py common-verify-authenticity
```

* Verify a card authenticity using pycryptodomex backend:
```commandline
python3 satochip_cli.py common-verify-authenticity --backend pycryptodomex
```

## Sign Nostr event

_Note: to use this functionality you will need a card with the Satochip applet [v0.14-0.2](https://github.com/Toporin/SatochipApplet/releases/tag/v0.14-0.2) or higher._

* Import a private key on slot #0:
```commandline
python3 satochip_cli.py --verbose satochip-import-privkey --keyslot 0 --privkey aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
```

* Get the corresponding publick key:
```commandline
python3 satochip_cli.py --verbose satochip-get-pubkey-from-keyslot --keyslot 0
```

* Sign Nostr event 
```commandline
python3 satochip_cli.py --verbose satochip-sign-nostr-event --keyslot 0 --message "Hello, world" --kind 1 --broadcast
```

* Alternatively, you can import a BIP39 seed and sign with a key derived from a given path:
```commandline
python3 satochip_cli.py --verbose satochip-import-unencrypted-mnemonic
```

```commandline
python3 satochip_cli.py --verbose satochip-sign-nostr-event --path "m/44'/0'/0'/0/0" --message "Hello, world" --kind 1 --broadcast
```

## Satocash operations 

* setup card (once):

```commandline
python3 satochip_cli.py --verbose common-initial-setup --label "my label"
```

* Get status:

```commandline
python3 satochip_cli.py --verbose satocash-get-status
```

* Get balance:

```commandline
python3 satochip_cli.py --verbose satocash-get-balances --unit "sat"
```

* Import token v4:

```commandline
python3 satochip_cli.py --verbose satocash-import-tokenv4 --tokenv4 "..."
```

* Export token v4:

```commandline
python3 satochip_cli.py --verbose satocash-export-tokenv4 --unit "sat" --amount "10"
```

* import mint
```commandline
python3 satochip_cli.py satocash-import-mint --url https://testnut.cashu.space
```

* export mint
```commandline
python3 satochip_cli.py satocash-export-mint --index 0
```

* import keyset
```commandline
python3 satochip_cli.py satocash-import-keyset --keyset-id 00dff24b65d02838 --mint-index 0 --unit sat
```

* export keyset
```commandline
python3 satochip_cli.py satocash-export-keysets --index-list "1"
```

* get publick key for P2PK proof (NUT11)
```commandline
python3 satochip_cli.py satocash-get-bip32-extendedkey
```

* import proof with P2PK_path for locked script
```commandline
python3 satochip_cli.py satocash-import-proof --keyset-index 0 --amount 1 --secret "..." --unblinded-key "..." --p2pk-path "..."
```

* export proof
```commandline
python3 satochip_cli.py satocash-export-proofs --index-list "0"
```

* export P2PK signature for locked script
```commandline
python3 satochip_cli.py satocash-export-p2pk-sig --index 0
```

* export tokenv4 for a given amount and unit
```commandline
python3 satochip_cli.py satocash-export-tokenv4 --unit "sat" --amount 8
```

## Satodime operations

* Get NDEF info:
```commandline
python3 satochip_cli.py common-get-card-ndef
```

* Set NDEF policy to 1 (static NDEF):
```commandline
python3 satochip_cli.py common-set-card-ndef --policy 1
```

* Set NDEF policy to 1 (static NDEF) and NDEF data to "org.satochip.satodimeapp":
```commandline
python3 satochip_cli.py common-set-card-ndef --policy 1 --ndef 002ad40f18616e64726f69642e636f6d3a706b676f72672e7361746f636869702e7361746f64696d65617070
```