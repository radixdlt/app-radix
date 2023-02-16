## Setting Up Ledger Nano S Device

### Prerequisites
The instruction below assumes Python 3.x installed and configured.

### Installation Of LedgerBlue Loader App
With Python installed, installation of `ledgerblue` app can be done as follows:
```shell
# python -m pip install ledgerblue
```
This method works fine on Linux, Mac and Windows.

### Development Device Setup (Nano S)
> ☣️ ONLY Use a dedicated Ledger device for development. Don't use one with "funds on".

The device used for development is configured with specific seed phrase, so generated keys could be predicted.
This is necessary for testing purposes.

#### Hardware Reset (needed only if device was in use)
In order to reset device to factory defaults, follow steps below:
- Plug device and enter PIN to unlock
- Enter Setting
    - Navigate to "Settings" menu and long press both buttons
- Select Settings -> Security -> Reset device
- Press right button until "Reset device" text appears
- Press both buttons to confirm choice
- Enter PIN to confirm hardware reset

#### Enter Recovery Mode
> ⚠️ Recovery mode could be entered only if device is brand new or after hardware reset. If device fails to enter recovery mode (shows PIN entry screen shortly after `Recovery``message), then device must be reset to factory settings.️

- Unplug device, press right button and while keeping it pressed, plug device back.
- Wait until "Recovery" word appears and release right button

#### Load development seed phrase and PIN
Use following command to load development seed phrase and set PIN on the development device to `5555`:
```sh
python3 -m ledgerblue.hostOnboard --apdu --id 0 --prefix "" --passphrase "" --pin 5555 --words "equip will roof matter pink blind book anxiety banner elbow sun young"
```
The process takes some time (few minutes) to finish.

### Flashing Firmware
Instruction below describes flashing of debug version of application.

#### Linux/Mac

Unzip binary package (usually named like ) into some directory. Go to that directory and run following command:
```shell
python -m ledgerblue.loadApp \
--path "44'/1022'" \
--curve secp256k1 \
--tlv \
--targetId 0x31100004 \
--delete \
--fileName bin/app.hex \
--appName Radix \
--dataSize $((0x`cat debug/app.map |grep _envram_data | tr -s ' ' | cut -f2 -d' '|cut -f2 -d'x'` - 0x`cat debug/app.map |grep _nvram_data | tr -s ' ' | cut -f2 -d' '|cut -f2 -d'x'`)) \
--icon 0100000000ffffff00ffffffffffffffffffe1fffdfffce7fe4ffe1fffbfffffffffffffffffffffff \
--rootPrivateKey b5b2eacb2debcf4903060e0fa2a139354fe29be9e4ac7c433f694a3d93297eaa
```

### Windows

Detailed instruction for sideloading of the app can be found [here](https://docs.radixdlt.com/main/user-applications/ledger-app-sideload-windows.html).
