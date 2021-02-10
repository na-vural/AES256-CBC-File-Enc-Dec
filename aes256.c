#include "aes256.h"

static const uint8_t s_box[256] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static const uint8_t inv_s_box[256] = {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
                                0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
                                0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
                                0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
                                0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
                                0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
                                0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
                                0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
                                0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
                                0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
                                0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
                                0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
                                0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
                                0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
                                0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
                                0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

static const uint8_t mul_matrix[4][4] = {  {0x02, 0x03, 0x01, 0x01},
                                    {0x01, 0x02, 0x03, 0x01},
                                    {0x01, 0x01, 0x02, 0x03},
                                    {0x03, 0x01, 0x01, 0x02}};

static const uint8_t inv_mul_matrix[4][4] = {  {0x0e, 0x0b, 0x0d, 0x09},
                                        {0x09, 0x0e, 0x0b, 0x0d},
                                        {0x0d, 0x09, 0x0e, 0x0b},
                                        {0x0b, 0x0d, 0x09, 0x0e}};

static const uint8_t Rcon[10][4] = {   {0x01, 0x00, 0x00, 0x00},
                                {0x02, 0x00, 0x00, 0x00},
                                {0x04, 0x00, 0x00, 0x00},
                                {0x08, 0x00, 0x00, 0x00},
                                {0x10, 0x00, 0x00, 0x00},
                                {0x20, 0x00, 0x00, 0x00},
                                {0x40, 0x00, 0x00, 0x00},
                                {0x80, 0x00, 0x00, 0x00},
                                {0x1b, 0x00, 0x00, 0x00},
                                {0x36, 0x00, 0x00, 0x00}};

/* Function declarations used for both decrypt and encrypt */
static uint8_t gmul(uint8_t a, uint8_t b); //Multiplication in Galois Field.
static bool compare256BitKeys(const void *const first_key, const void *const second_key); //256 bit key comparision.
static void expan256BitKey(uint8_t expanded_key[][4], const uint8_t *const key); //256 bit key expansion.
static void addRoundKey(uint8_t state[][4],
                 const uint8_t expanded_key[][4],
                 const uint8_t round_num); //Because of XOR, this function is also inverse of itself.
static void createState(uint8_t state[][4], const uint8_t *const block);
static void writeOut(uint8_t *const block, uint8_t state[][4]);

/* Function declarations about AES256 CBC MODE Encrypt */
void aes256Encrypt(uint8_t *const block,
                   const uint8_t *const cipher);
static void subBytes(uint8_t state[][4]);
static void shiftRows(uint8_t state[][4]);
static void mixCols(uint8_t state[][4]);

/* Function declarations about AES256 CBC MODE Decrypt */
void aes256Decrypt(uint8_t *const block,
                   const uint8_t *const cipher);
static void inv_subBytes(uint8_t state[][4]);
static void inv_shiftRows(uint8_t state[][4]);
static void inv_mixCols(uint8_t state[][4]);

/*
 * Multiplication in Galois Field GF(2^8)
 * The code taken from https://en.wikipedia.org/wiki/Rijndael_MixColumns
 */
static uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    uint8_t check = 0;
    for (uint8_t i = 0 ; i < 8 ; i++) {
        if ( (b & 1) != 0 ) {
            p ^= a;
        }
        
        check = (a & 0x80);
        a <<= 1;
        if ( check != 0 ) {
            a ^= 0x1b;
        }
        b >>= 1;
    }

    return p;
}

/*
 * This function splits 256 bit key into biggest chunks supported by the computer arch.
 * Then calculate XOR, if keys are equal than XOR returns 0. Otherwise this means that 
 * keys are not equal and XOR returns non-zero result.
 */
static bool compare256BitKeys(const void *const first_key, const void *const second_key)
{
    for (uint8_t i = 0 ; i < 32 ; i += sizeof(uintmax_t)) {
        if ( ( *((uintmax_t *)(((uint8_t *)first_key)+i)) ^ *((uintmax_t *)(((uint8_t *)second_key)+i)) ) != 0 ) {
            return false;
        }
    }
    return true;
}

/*
 * This is 256 bit key expansion for the AES encryption-decryption.
 * Basically takes function takes 256 bit key and calculate different keys
 * for each encryption-decryption rounds.
 */
static void expan256BitKey(uint8_t expanded_key[][4], const uint8_t *const key)
{
    memcpy(expanded_key[0], key, 32);
    for (uint8_t i = 8 ; i < (4*(NR256+1)) ; i++) {
        if ( i % 8 == 4 ) {
            for (uint8_t j = 0 ; j < 4 ; j++) {
                expanded_key[i][j] = s_box[expanded_key[i-1][j]];
                expanded_key[i][j] ^= expanded_key[i-8][j];
            }
        } else if ( i % 8 == 0 ) {
            for (uint8_t j = 0 ; j < 4 ; j++) {
                expanded_key[i][j] = expanded_key[i-1][(j+1) % 4];
                expanded_key[i][j] = s_box[expanded_key[i][j]];
                expanded_key[i][j] ^= Rcon[(i/8) - 1][j];
                expanded_key[i][j] ^= expanded_key[i-8][j];
            }
        } else {
            for (uint8_t j = 0 ; j < 4 ; j++) {
                expanded_key[i][j] = expanded_key[i-1][j];
                expanded_key[i][j] ^= expanded_key[i-8][j];
            }
        }
    }
}

/*
 * This function takes the AES's state and XOR the key pair for the given round.
 */
static void addRoundKey(uint8_t state[][4], const uint8_t expanded_key[][4], const uint8_t round_num)
{
    for (uint8_t i = 0 ; i < 4 ; i++) {
        for (uint8_t j = 0 ; j < 4 ; j++) {
            state[j][i] ^= expanded_key[round_num*4 + i][j];
        }
    }
}

/*
 * This is the most important structre of the encryption-decryption process.
 * State is the 4x4 matrix. Data that will be encrypted or decrypted is placed in
 * this matrix. Data must be placed from top to bottom, not from left to right.
 * This function basically takes a data block and put the data to the state
 * appropriately for the state structure.
 */
static void createState(uint8_t state[][4], const uint8_t *const block)
{
    for (uint8_t i = 0 ; i < 4 ; i++) {
        for (uint8_t j = 0 ; j < 4 ; j++) {
            state[i][j] = *(block + i + 4*j);
        }
    }
}

static void writeOut(uint8_t *const block, uint8_t state[][4])
{
    for (uint8_t i = 0 ; i < 4 ; i++) {
        for (uint8_t j = 0 ; j < 4 ; j++) {
            *(block + i + 4*j) = state[i][j];
        }
    }
}

void aes256Encrypt(uint8_t *const block, const uint8_t *const cipher)
{
    uint8_t state[4][4];
    static uint8_t key[4][8];
    static uint8_t expanded_key[(NR256+1)*4][4];

/*
    If given cipher same as the previous key than new key expansion is not applied.
    Cipher must not be '\0'.
*/
    if (compare256BitKeys(key, cipher) == false) {
        memcpy(key[0], cipher, 32);
        expan256BitKey(expanded_key, key[0]);
    }

    createState(state, block);
    addRoundKey(state, expanded_key, 0); //Zeroth round. Initialization step.

    for (uint8_t i = 1 ; i < NR256 ; i++) { //First round to last_round - 1
        subBytes(state);
        shiftRows(state);
        mixCols(state);
        addRoundKey(state, expanded_key, i);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, expanded_key, NR256); //Last round

    writeOut(block, state);
}

/*
 * This takes the state matrix and shifts data of the state
 * with the sbox data.
 */
static void subBytes(uint8_t state[][4])
{
    for (uint8_t i = 0 ; i < 4 ; i++) {
        for (uint8_t j = 0 ; j < 4 ; j++) {
            state[i][j] = s_box[state[i][j]];

        }
    }
}

/*
 * This shift the state rows.
 * First row is constant.
 * Second row cyclically shifted to the left one time.
 * Third row cyclically shifted to the left two times.
 * Fourth row cyclically shifted to the left three times.
 */
static void shiftRows(uint8_t state[][4])
{
    uint8_t temp_byte[4];
    for (uint8_t i = 1 ; i < 4 ; i++) {
        for (uint8_t j = 0 ; j < 4 ; j++) {
            temp_byte[j] = state[i][(4+((j+i) % 4)) % 4];
        }
        for (uint8_t j = 0 ; j < 4 ; j++) {
            state[i][j] = temp_byte[j];
        }
    }
}

/*
 * This function applies matrix multiplication to the state's columns with a special matrix.
 * The multiplication and addition must be applied in Galois Field.
 */
static void mixCols(uint8_t state[][4])
{
    uint8_t temp_byte[4];
    for (uint8_t j = 0 ; j < 4 ; j++) {
        for (uint8_t i = 0 ; i < 4 ; i++) {
            temp_byte[i] = gmul(mul_matrix[i][0], state[0][j]);
            temp_byte[i] ^= gmul(mul_matrix[i][1], state[1][j]);
            temp_byte[i] ^= gmul(mul_matrix[i][2], state[2][j]);
            temp_byte[i] ^= gmul(mul_matrix[i][3], state[3][j]);
        }
        for (uint8_t i = 0 ; i < 4 ; i++) {
            state[i][j] = temp_byte[i];
        }
    }
}

/*
 * This is the reverse of the aes256Encrypt()
 * Round number for the expanded key starts from the end
 * Also functions is inverse
 */
void aes256Decrypt(uint8_t *const block,
                   const uint8_t *const cipher)
{
    uint8_t state[4][4];
    static uint8_t key[4][8];
    static uint8_t expanded_key[(NR256+1)*4][4];

/*
    If given cipher same as the previous key than new key expansion is not applied.
    Cipher must not be '\0'.
*/
    if (compare256BitKeys(key, cipher) == false) {
        memcpy(key[0], cipher, 32);
        expan256BitKey(expanded_key, key[0]);
    }

    createState(state, block);
    addRoundKey(state, expanded_key, NR256); //Starts with the last round key

    for (uint8_t i = (NR256 - 1) ; i > 0 ; i--) {
        inv_shiftRows(state);
        inv_subBytes(state);
        addRoundKey(state, expanded_key, i);
        inv_mixCols(state);
    }

    inv_shiftRows(state);
    inv_subBytes(state);
    addRoundKey(state, expanded_key, 0);
    writeOut(block, state);
}

//Use inv_s_box instead of s_box
static void inv_subBytes(uint8_t state[][4])
{
    for (uint8_t i = 0 ; i < 4 ; i++) {
        for (uint8_t j = 0 ; j < 4 ; j++) {
            state[i][j] = inv_s_box[state[i][j]];

        }
    }
}

//Cyclically shift to the right.
//Same count with shiftRows.
static void inv_shiftRows(uint8_t state[][4])
{
    uint8_t temp_byte[4];
    for (uint8_t i = 1 ; i < 4 ; i++) {
        for (uint8_t j = 0 ; j < 4 ; j++) {
            temp_byte[j] = state[i][(4+((j-i) % 4)) % 4];
        }
        for (uint8_t j = 0 ; j < 4 ; j++) {
            state[i][j] = temp_byte[j];
        }
    }
}

//Galois Field multiplication with inv_mul_matrix
static void inv_mixCols(uint8_t state[][4])
{
    uint8_t temp_byte[4];
    for (uint8_t j = 0 ; j < 4 ; j++) {
        for (uint8_t i = 0 ; i < 4 ; i++) {
            temp_byte[i] = gmul(inv_mul_matrix[i][0], state[0][j]);
            temp_byte[i] ^= gmul(inv_mul_matrix[i][1], state[1][j]);
            temp_byte[i] ^= gmul(inv_mul_matrix[i][2], state[2][j]);
            temp_byte[i] ^= gmul(inv_mul_matrix[i][3], state[3][j]);
        }
        for (uint8_t i = 0 ; i < 4 ; i++) {
            state[i][j] = temp_byte[i];
        }
    }
}
