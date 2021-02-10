# AES256-CBC File Enc/Dec
This is the EHB110E final project. Aim is that encrypt one or more files into a single file using AES256-CBC and decrypt this single file by preserving relative pathways of the encrypted files.

## Installation
Clone the repo and compile with `gcc aes256cbc_file_enc_dec.c`.

## Usage
```
AES256 CBC File Encryptor-Decryptor
Encryption Usage: ./a.out -k [KEY] -e -o [OUTPUT FILE] -i [INPUT FILE(S)-DIR(S)]
Decryption Usage: ./a.out -k [KEY] -d -i [INPUT FILE]
-k [KEY]            The key that is used in encryption and decryption.
                    Key must be given in the first place.
                    Key length should be 256 bit namely 32 byte.
                    If key is less than 256 bit, than key padded with zero (ASCII zero not the '\\0')
                    If key is greater than 256 bit, than program terminates.
After the key parameter one of the two options must be specified, encryption or decryption:
-e                  Encryption
                    When encryption is choosen, -o [OUTPUT FILE] -i [INPUT FILE(S)-DIR(S)]  must be given.
                    In encryption, output file must be given first, than input files and dirs are specified.
                    There must be one output file, but number of input files-dirs can be more than one in encryption.
-d                  Decryption
                    In decryption the given input file must not be more than one. And the input file must be
                    encrypted with this program. Otherwise program terminates.
-i [INPUT FILE(S)]  Input file(s) specifier
                    In encryption this specify files and dirs that will be encrypted into single file.
                    In decryption this specify the file that will be decrypted. The file must be one that was encrypted with this program.
-o [OUTPUT FILE]    Output file specifier
                    This option must be used only in encryption. And specify name of the output file that
                    includes the encrypted files and dirs.
```

## TODO
- Output file option for decryption will be added.
- Some tricks for faster encryption and decryption will be removed to make secure the algorithm.
- To be compatible with fips-197, key expansion algorithm will be changed and expanded key will be stored as 4 by (NR256+1)*4 matrix instead of (NR256+1)*4 by 4 matrix.
