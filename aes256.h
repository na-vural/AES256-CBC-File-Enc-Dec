#ifndef _AES256_H_
#define _AES256_H_

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#define NR256 14 //Number of rounds specified by NIST for AES256 encryption decryption

void aes256Encrypt(uint8_t *const block,
                   const uint8_t *const cipher);

void aes256Decrypt(uint8_t *const block,
                   const uint8_t *const cipher);

#endif // _AES256_H_
