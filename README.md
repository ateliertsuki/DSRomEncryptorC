# DSRomEncryptorC
Reimplementation (Fork?) of Gericom's DSRomEncryptor, now written in GLibC.

Tool to prepare DS and DSi roms for use on a cartridge. The tool inserts the necessary NTR and TWL blowfish key blocks and encrypts the NTR secure area (0x4000-0x4800).

For further details, visit Gericom's original [repository](https://github.com/Gericom/DSRomEncryptor)

## Compile
`make`

## Cleanup
`make clean`

## Usage
`dsromencryptor [--dsidev] input.nds output.nds`

## License
DSRomEncryptor is licensed under the MIT License, see [LICENSE](./LICENSE.txt) for more information.
