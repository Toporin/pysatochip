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

    

