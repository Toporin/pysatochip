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

