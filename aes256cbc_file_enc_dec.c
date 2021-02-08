#include <linux/limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h> //bool
#include <errno.h> //errno
#include <dirent.h> //readdir opendir
#include <unistd.h> //getcwd chdir
#include <limits.h>
#include <time.h>
#include <sys/stat.h>
#define NR256 14 //Number of rounds specified by NIST for AES256 encryption decryption

typedef struct _path_list{
        struct _path_list *next;
        char path[PATH_MAX];
}path_list;

typedef struct _data_header{
        uint64_t file_size;
        uint16_t padding_size;
        uint16_t path_name_size;
        uint8_t iv_vector[16];
}data_header_struct;

/***************** CONSTANT DATA *****************/

const char file_id[] = "NAV-AES256CBC";

const uint8_t s_box[256] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
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

const uint8_t inv_s_box[256] = {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
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

const uint8_t mul_matrix[4][4] = {{0x02, 0x03, 0x01, 0x01},
                            {0x01, 0x02, 0x03, 0x01},
                            {0x01, 0x01, 0x02, 0x03},
                            {0x03, 0x01, 0x01, 0x02}};

const uint8_t inv_mul_matrix[4][4] = {{0x0e, 0x0b, 0x0d, 0x09},
                            {0x09, 0x0e, 0x0b, 0x0d},
                            {0x0d, 0x09, 0x0e, 0x0b},
                            {0x0b, 0x0d, 0x09, 0x0e}};

const uint8_t Rcon[10][4] = {{0x01, 0x00, 0x00, 0x00},
                       {0x02, 0x00, 0x00, 0x00},
                       {0x04, 0x00, 0x00, 0x00},
                       {0x08, 0x00, 0x00, 0x00},
                       {0x10, 0x00, 0x00, 0x00},
                       {0x20, 0x00, 0x00, 0x00},
                       {0x40, 0x00, 0x00, 0x00},
                       {0x80, 0x00, 0x00, 0x00},
                       {0x1b, 0x00, 0x00, 0x00},
                       {0x36, 0x00, 0x00, 0x00}};

/***************** FUNCTION DECLARATIONS *****************/

void usage();
void progressBar(uint16_t increment, uint64_t *total);

void decryption(char file[], uint8_t *key);
void changeAndCreateDir(char file_path[]);

void encryption(char *files[], uint64_t files_arr_size, char *fout_name, uint8_t *key);
void randIV128(uint8_t iv_vector[]);
void filesInDir(char dir[], path_list **paths);
void addToPathList(char file_name[], path_list **paths);
uint32_t redesignPathList(path_list **paths);
/* Function declarations used for both decrypt and encrypt */
uint8_t gmul(uint8_t a, uint8_t b); //Multiplication in Galois Field.
void xor128Bit(uint8_t *const first, uint8_t *const second); //XOR second data into first data. For CBC mode.
bool compare256BitKeys(const void *const first_key, const void *const second_key); //256 bit key comparision.
void expan256BitKey(uint8_t expanded_key[][4], const uint8_t *const key); //256 bit key expansion.
void addRoundKey(uint8_t state[][4],
                 const uint8_t expanded_key[][4],
                 const uint8_t round_num); //Because of XOR, this function is also inverse of itself.
void createState(uint8_t state[][4], const uint8_t *const block);
void writeOut(uint8_t *const block, uint8_t state[][4]);
/* Function declarations about AES256 CBC MODE Encrypt */
uint8_t cbcModeEncrypt( uint8_t *const data_ptr,
                        const uint64_t data_size,
                        uint8_t *const iv_vector,
                        const uint8_t *const cipher);
void aes256Encrypt(uint8_t *const block,
                   const uint8_t *const cipher);
void subBytes(uint8_t state[][4]);
void shiftRows(uint8_t state[][4]);
void mixCols(uint8_t state[][4]);
/* Function declarations about AES256 CBC MODE Decrypt */
uint8_t cbcModeDecrypt(uint8_t *const data_ptr,
                    const uint64_t data_size,
                    uint8_t *const iv_vector,
                    const uint8_t *const cipher);
void aes256Decrypt(uint8_t *const block,
                   const uint8_t *const cipher);
void inv_subBytes(uint8_t state[][4]);
void inv_shiftRows(uint8_t state[][4]);
void inv_mixCols(uint8_t state[][4]);

/***************** MAIN AND FUNCTIONS *****************/

int main(int argc, char *argv[]) {
    //Begin time save, srand for random data, setvbuf for stdout buffer size.
    time_t exec_begin, exec_end;
    exec_begin = time(NULL);
    srand(time(NULL));
    setvbuf(stdout, NULL, _IONBF, 0); // turn off buffering for stdout
    //Check the command line arguments.
    if ( argc < 6 ) {
        usage();
        return 1;
    } else if ( strcmp(argv[1], "-k") != 0 ) {
        usage();
        return 1;
    } else if ( strcmp(argv[3], "-e") == 0 ) {
        if ( argc < 8 ) {
            usage();
            return 1;
        } else if ( strcmp(argv[4], "-o") != 0 ) {
            usage();
            return 1;
        } else if ( strcmp(argv[6], "-i") != 0 ) {
            usage();
            return 1;
        }
    } else if ( strcmp(argv[3], "-d") == 0 ) {
        if ( argc != 6 ) {
            usage();
            return 1;
        } else if ( strcmp(argv[4], "-i") != 0 ) {
            usage();
            return 1;
        }
    } else {
        usage();
        return 1;
    }
    //Check the key size
    if ( strlen(argv[2]) > 32 ) {
        printf("ERROR: Key size must be less than or equals to 256 bit, 32 byte.\n\n");
        usage();
        return 1;
    }
    //Saving the key, if less than 32 byte also pedding the key with 0.
    uint8_t key[32];
    memcpy(key, argv[2], strlen(argv[2]));
    if ( strlen(argv[2]) < 32 ) {
        printf("[WARNING] Key size is less than 256 bit, 32 byte.\n");
        printf("[WARNING] Missing key bytes will be padded with ASCII 0 (not '\\0')\n");
        memset(key + strlen(argv[2]), '0', 32 - strlen(argv[2]));
    }
    //Encryption or decryption depending on the cli arguments.
    if ( strcmp(argv[3], "-e") == 0 ) {
        encryption(&argv[7], argc - 7, argv[5], key);
    } else if ( strcmp(argv[3], "-d") == 0 ) {
        decryption(argv[5], key);
    }
    //Finish, total time calculation and print the total time
    exec_end = time(NULL);
    printf("in %ld second.\n", exec_end - exec_begin);

    return 0;
}

void usage()
{
    printf("AES256 CBC File Encryptor-Decryptor\n\n");
    printf("Encryption Usage: ./a.out -k [KEY] -e -o [OUTPUT FILE] -i [INPUT FILE(S)-DIR(S)]\n");
    printf("Decryption Usage: ./a.out -k [KEY] -d -i [INPUT FILE]\n\n");
    printf("-k [KEY]            The key that is used in encryption and decryption.\n");
    printf("                    Key must be given in the first place.\n");
    printf("                    Key length should be 256 bit namely 32 byte.\n");
    printf("                    If key is less than 256 bit, than key padded with zero (ASCII zero not the '\\0')\n");
    printf("                    If key is greater than 256 bit, than program terminates.\n\n");
    printf("After the key parameter one of the two options must be specified, encryption or decryption:\n\n");
    printf("-e                  Encryption\n");
    printf("                    When encryption is choosen, -o [OUTPUT FILE] -i [INPUT FILE(S)-DIR(S)]  must be given.\n");
    printf("                    In encryption, output file must be given first, than input files and dirs are specified.\n");
    printf("                    There must be one output file, but number of input files-dirs can be more than one in encryption.\n\n");
    printf("-d                  Decryption\n");
    printf("                    In decryption the given input file must not be more than one. And the input file must be\n");
    printf("                    encrypted with this program. Otherwise program terminates.\n\n");
    printf("-i [INPUT FILE(S)]  Input file(s) specifier\n");
    printf("                    In encryption this specify files and dirs that will be encrypted into single file.\n");
    printf("                    In decryption this specify the file that will be decrypted. The file must be one that was encrypted with this program.\n\n");
    printf("-o [OUTPUT FILE]    Output file specifier\n");
    printf("                    This option must be used only in encryption. And specify name of the output file that\n");
    printf("                    includes the encrypted files and dirs.\n\n");
}

/*
 * Programmable progress bar. When you give non-NULL pointer it
 * save the number in this pointer.
 * Than you can call this function everywhere of this code.
 */
void progressBar(uint16_t increment, uint64_t *total)
{
    static uint64_t total_size;
    static uint64_t inc_memory;
    static char bar[101];
    static uint8_t percent = 0;
    if ( (total_size != 0) && (total == NULL) ) {
        inc_memory += increment;
        percent = 100 * ((float)inc_memory / total_size);
        memset((void *)bar, '#', percent);
        printf("%%%u [%-100s]\r", percent, bar);
    } else if ( total != NULL ) {
        total_size = *total;
        inc_memory = 0;
        memset((void *)bar, '\0', 101);
        printf("[+] %ju bytes will be processed.\n\n", total_size);
    } else {
        printf("[ERROR] Wrong progress bar initialization.");
        exit(1);
    }
}

void decryption(char file[], uint8_t *key)
{
    //File check and decryption size calculation.
    uint64_t decryption_size;
    printf("%s", "[*] Initializing the given file...\n");
    {
        struct stat check;
        if (lstat(file, &check) == -1) {
            printf("\n[ERROR] %s: %s\n", file, strerror(errno));
            exit(errno);
        }
        if ( (check.st_mode & S_IFMT) != S_IFREG ) {
            printf("\n[ERROR] %s: %s\n", file, "It is not a regular file.");
            exit(1);
        }
        decryption_size = check.st_size;
    }
    //Open the encrypted file
    FILE *fin;
    char file_id_check[sizeof(file_id)];
    if ( (fin = fopen(file, "rb")) == NULL ) {
        printf("\n[ERROR] %s: %s\n", file, strerror(errno));
        exit(errno);
    }
    //Check the file ID.
    printf("%s", "[+] File ID checked.\n");
    if ( fread(file_id_check, sizeof(file_id_check), 1, fin) != 1 ) {
        printf("\n[ERROR] Unkown error occured.\n");
        fclose(fin);
        exit(errno);
    } 
    if ( strcmp(file_id_check, file_id) != 0 ) {
        printf("\n[ERROR] Given file %s can not encrypted by this program.\n", file);
        fclose(fin);
        exit(1);
    }
    //Saving the current directory. Because it will change and must be restored.
    char base[PATH_MAX];
    getcwd(base, PATH_MAX);
    //Progress bar initialization and beginning of the process.
    printf("%s", "[+] Initialization successful.\n[*] Decryption and extraction was started.\n");
    progressBar(0, &decryption_size);
    progressBar(sizeof(file_id_check), NULL);
    //Not wait to EOF, wait for the last byte.
    while ( ftell(fin) != (long)decryption_size ) {
        FILE *fout; //for output file
        data_header_struct data_header; //holds data header section in the encrypted file
        struct stat check; //for checking the output file existance
        uint64_t size_for_dec; //holds decryption size
        uint8_t *dec_data_ptr; //holds pointer to the data that will decrypted.
        char *file_name; //Pointer points to just the name of the file not the path.
        if ( fread(&data_header, sizeof(data_header), 1, fin) != 1 ) {
            printf("\n[ERROR] Unkown error occured.\n");
            fclose(fin);
            exit(errno);
        }
        progressBar(sizeof(data_header), NULL);
        //dec size calc
        size_for_dec = data_header.path_name_size;
        size_for_dec += data_header.file_size;
        size_for_dec += data_header.padding_size;
        //memory for the encrypted section that will decrypted
        if ( (dec_data_ptr = (uint8_t *)malloc(size_for_dec)) == NULL ) {
            printf("\n[ERROR] %s", strerror(errno));
            exit(errno);
        }
        //read into mem
        if ( fread(dec_data_ptr, 1, size_for_dec, fin) != size_for_dec ) {
            printf("\n[ERROR] Unkown error occured.\n");
            fclose(fin);
            exit(errno);
        }
        //decryption of the memory location
        cbcModeDecrypt(dec_data_ptr, size_for_dec, data_header.iv_vector, key);
        //check if the file path length is same with the header or not.
        //if not equal, than this means wrong decryption.
        if ( data_header.path_name_size != (strlen((char *)dec_data_ptr) + 1) ) {
            printf("\n[WRONG ENC KEY] Wrong encryption key. Please be sure that the encryption key is true.\n");
            free(dec_data_ptr);
            fclose(fin);
            exit(1);
        }
        //change and create dir for the saving the file.
        changeAndCreateDir((char *)dec_data_ptr);
        //just the name of the file
        file_name = strrchr((char *)dec_data_ptr, '/') + 1;
        //overflow check
        if ( lstat(file_name, &check) == 0 ) {
            if ( (check.st_mode & S_IFMT) == S_IFREG ) {
                printf("\"%s\" is exist, do you want to overflow?%-69s\n[y/N] -> ", dec_data_ptr, " ");
                switch (getchar()) {
                    case 'Y':
                    case 'y':
                        while ((getchar()) != '\n');
                        break;
                    case '\n':
                        free(dec_data_ptr);
                        chdir(base);
                        continue;
                    default:
                        while ((getchar()) != '\n');
                        free(dec_data_ptr);
                        chdir(base);
                        continue; //Continue the while loop not switch statement.
                }
            }
        }
        //opening the file decrypted file
        if ( (fout = fopen(file_name, "wb")) == NULL ) {
            printf("\n[ERROR] %s: %s\n", file_name, strerror(errno));
            fclose(fin);
            exit(errno);
        }
        //writing the decrypted data
        if ( fwrite(dec_data_ptr + data_header.path_name_size, 1, data_header.file_size, fout) != data_header.file_size ) {
            printf("\n[ERROR] %s\n", strerror(errno));
            fclose(fout);
            fclose(fin);
            exit(errno);
        }
        //cleaning up
        fclose(fout);
        free(dec_data_ptr);
    }
    //end of the process
    fclose(fin);
    printf("%s", "\n[*] Files(s) are decrypted without errors ");

}

/*
 * This function changes the current dir but if an error ocurred
 * look the dir is exist or not. If dir is not exist than
 * create a dir and changes current dir.
 */
void changeAndCreateDir(char file_path[])
{
    //Copy the file_path because we use string token.
    char copy[strlen(file_path)];
    char *file_name;
    char *token;
    strcpy(copy, file_path);
    file_name = strrchr(copy, '/') + 1;
    //First tokenize
    token = strtok(copy, "/");
    //Until last token loop will continue
    while (token != file_name) {
        if ( chdir(token) != 0 ) {
            //Error check. If error is occured because dir is not exist
            //than create a new dir.
            if ( errno == ENOENT ) {
                if ( mkdir(token, 0777) != 0 ) {
                    printf("\n[ERROR] %s", strerror(errno));
                    exit(errno);
                }
                if ( chdir(token) != 0 ) {
                    printf("\n[ERROR] %s\n", strerror(errno));
                    exit(errno);
                }
            } else {
                printf("\n[ERROR] %s\n", strerror(errno));
                exit(errno);
            }
        }
        //Continue the tokenize
        token = strtok(NULL, "/");
    }
}


/*
 * Main encryption function for the file processes.
 */
void encryption(char *files[], uint64_t files_arr_size, char *out_name, uint8_t *key)
{
    /*
     * Check whether the given file or dir names is valid or not.
     */
    for (uint64_t i = 0 ; i < files_arr_size ; i++) {
        struct stat check;
        if (lstat(files[i], &check) == -1) {
            printf("\n[ERROR] %s: %s\n", files[i], strerror(errno));
            exit(errno);
        }
    }
    /*
     * Check whether the output file is exist or not.
     */
    {
        struct stat check;
        if ( lstat(out_name, &check) != -1 ) {
            if ( (check.st_mode & S_IFMT) != S_IFDIR ) {
                printf("\n[ERROR] The output file \"%s\" is exist. Process cancelled.\n", out_name);
                exit(1);
            }
        }
    }
    /* 
     * Save the current dir because filesInDir() function will change
     * the current dir and we must restore it.
     */
    char base[PATH_MAX];
    getcwd(base, PATH_MAX);
    /*
     * Create a linked list to save file's paths.
     */
    path_list *paths = NULL;
    /*
     * This loop check if the given file is dir or regular file.
     * In case of dir, filesInDir func will be called.
     * In case of reg file, just add this file to the file path list.
     */
    printf("[*] Initializing files...\n");
    for (uint64_t i = 0 ; i < files_arr_size ; i++) {
        struct stat check;
        if ( lstat(files[i], &check) == -1 ) {
            printf("\n[ERROR] %s: %s\n", files[i], strerror(errno));
            exit(errno);
        }
        if ( (check.st_mode & S_IFMT) == S_IFREG ) {
            addToPathList(files[i], &paths);
        } else if ( (check.st_mode & S_IFMT) == S_IFDIR ) {
            filesInDir(files[i], &paths);
            if (chdir(base) != 0) {
                printf("\n[ERROR] %s: %s\n", "..", strerror(errno));
                exit(errno);
            }        
        }
    }
    //Redesing paths finds the same root for all files and
    //delete the duplicate file paths.
    uint32_t path_offset = redesignPathList(&paths);

    //start of the encryption
    printf("%s", "[+] Initialization successful.\n[*] Calculating encryption size...\n");
    path_list *temp = paths;
    uint64_t header_size = 0; //This also specifys how many files will be encrypted.
    uint64_t total_enc_size = 0; //holds enc size for progress bar.
    struct stat check; //check for the files and their size
    while ( true ) {
        uint64_t file_size = 0;
        //This if is the last file, because while temp->next == NULL,
        //temp->path points to a file.
        if ( temp->next == NULL ) {
            //For one file there is one header section.
            header_size += 1;
            if ( lstat(temp->path, &check) == -1 ) {
                printf("\n[ERROR] %s: %s\n", temp->path, strerror(errno));
                exit(errno);
            }
            //Files and their paths will be encrypted.
            file_size = (uint64_t)check.st_size + strlen(temp->path + path_offset) + 2; //The "." dot and null char added to the file path.
            file_size += 16 - (file_size % 16);
            total_enc_size += file_size;
            break;
        }
        //this section for the temp->next != NULL, same process with above.
        header_size += 1;
        if ( lstat(temp->path, &check) == -1 ) {
            printf("\n[ERROR] %s: %s\n", temp->path, strerror(errno));
            exit(errno);
        }
        file_size = (uint64_t)check.st_size + strlen(temp->path + path_offset) + 2; //The "." dot and null char added to the file path.
        file_size += 16 - (file_size % 16);
        total_enc_size += file_size;
        temp = temp->next;
    }
    //Initialize the progress bar
    progressBar(0, &total_enc_size);
    
    //Open the output file that holds encrypted files.
    FILE *fout;
    temp = paths;
    if ( (fout = fopen(out_name, "wb+")) == NULL ) {
        printf("\n[ERROR] %s\n", strerror(errno));
        exit(errno);
    }
    //Write the file ID, this is NAV-AES256CBC\0
    if ( fwrite(file_id, sizeof(file_id), 1, fout) != 1 ) {
        printf("\n[ERROR] %s\n", strerror(errno));
        fclose(fout);
        exit(errno);
    }
    //Until last file, the for will continue
    for (uint64_t i = 0 ; i < header_size ; i++) {
        FILE *fin; //For the file that will encrypted into single file
        uint64_t encrypted_data_size;
        uint8_t *data_ptr; //holds malloc pointer, points to the file readed into mem.
        data_header_struct data_header; //data header
        struct stat check;
        //check the path and open the file with read byte mode.
        if (lstat(temp->path, &check) == -1) {
            printf("\n[ERROR] %s: %s\n", temp->path, strerror(errno));
            fclose(fout);
            exit(errno);
        }
        if ( (fin = fopen(temp->path, "rb")) == NULL ) {
            printf("\n[ERROR] %s\n", strerror(errno));
            fclose(fout);
            exit(errno);
        }
        //header calculations
        data_header.path_name_size = strlen(temp->path + path_offset) + 2; // With a "." dot and null char
        randIV128(data_header.iv_vector); //This will be used for encryption and saved to the header for decryption.
        data_header.file_size = (uint64_t)check.st_size;
        encrypted_data_size = data_header.file_size + data_header.path_name_size;
        data_header.padding_size = 16 - (encrypted_data_size % 16);
        //memory pointer for the file that will encrypted.
        data_ptr = (uint8_t *)malloc(encrypted_data_size + data_header.padding_size);
        if (data_ptr == NULL) {
            printf("\n[ERROR] %s", strerror(errno));
            exit(errno);
        }
        //This memset adds the dot beginning to the path. For example /Destop will be ./Desktop
        memset(data_ptr, '.', 1);
        strcpy((char *)(data_ptr + 1), temp->path + path_offset);
        //Read the as bytes.
        if (fread(data_ptr + data_header.path_name_size, sizeof(uint8_t), data_header.file_size, fin) != data_header.file_size) {
            printf("\n[ERROR] Unkown error occured.\n");
            fclose(fout);
            fclose(fin);
            exit(errno);
        }
        //Close the readed file.
        fclose(fin);
        //Encrypt the pathname and file itself.
        cbcModeEncrypt(data_ptr, encrypted_data_size, data_header.iv_vector, key);
        //Write the header holds info about encrypted file.
        if (fwrite(&data_header, sizeof(data_header), 1, fout) != 1) {
            printf("\n[ERROR] %s\n", strerror(errno));
            fclose(fout);
            fclose(fin);
            exit(errno);
        }
        //Write the encrypted file from memory to the output file.
        if (fwrite(data_ptr, sizeof(uint8_t), encrypted_data_size + data_header.padding_size, fout) != encrypted_data_size + data_header.padding_size) {
            printf("\n[ERROR] %s\n", strerror(errno));
            fclose(fout);
            fclose(fin);
            exit(errno);
        }
        //Cleaning up
        free(data_ptr);
        //Next to the new file
        temp = temp->next;
    }
    //Finish
    fclose(fout);
    printf("%s", "\n[*] File(s) are encrypted without errors ");
}

/*
 * This creates 128 bit random initialization vector.
 */
void randIV128(uint8_t iv_vector[])
{
    for (uint8_t i = 0 ; i < 16 ; i++) {
        *(iv_vector+i) = rand() % 256;
    }
}

/*
 * This function iterates in given directory, finds the files in this directory
 * and call addToPathList function to add this files into the list.
 */
void filesInDir(char dir[], path_list **paths)
{
    /* Check if given dir is valid or not. */
    struct stat check;
    if ( lstat(dir, &check) == -1 ) {
        printf("\n[ERROR] %s: %s\n", dir, strerror(errno));
        exit(errno);
    }
    
    /* Change active directory to given directory for iterative search. */
    if (chdir(dir) != 0) {
        printf("\n[ERROR] %s: %s\n", dir, strerror(errno));
        exit(errno);
    }

    /* 
     * Because we changed the current directory, when we use opendir(".")
     * we open the directory that given to the function as argument.
     */
    DIR *dir_ptr = opendir(".");
    struct dirent *d_enum;
    /* Until all the members of the dir is checked, while loop continues. */
    while ( (d_enum = readdir(dir_ptr)) != NULL ) {
        /* We eliminate the "." current dir and ".." parent dir specifiers. */
        if ( (strcmp(d_enum->d_name, ".") != 0) && (strcmp(d_enum->d_name, "..") != 0) ) {
            /* We check the member of the given dir, if it is valid or not. */
            if ( lstat(d_enum->d_name, &check) == -1 ) {
                printf("\n[ERROR] %s: %s\n", d_enum->d_name, strerror(errno));
                exit(errno);
            }
            /* We check the type of the member.
             * If the member is a regular file, than add this file to the path list.
             * Else if the member is a dir, than change current dir to this dir and iterate the function.
             */
            if ( (check.st_mode & S_IFMT) == S_IFREG ) {
                addToPathList(d_enum->d_name, &(*paths));
            } else if ( (check.st_mode & S_IFMT) == S_IFDIR ) {
                /* Change current directory to the member that resides in the directory that given to the function. */
                /* The if blocks is to check an error occured or not. */
                if (chdir(d_enum->d_name) != 0) {
                    printf("\n[ERROR] %s: %s\n", d_enum->d_name, strerror(errno));
                    exit(errno);
                }
                /* Because we changed the current dir, we iterate with "." current dir specifier. */
                filesInDir(".", &(*paths));
                /* After the iteration we back to the parent dir. */
                if (chdir("..") != 0) {
                    printf("\n[ERROR] %s: %s\n", "..", strerror(errno));
                    exit(errno);
                }
            }
        }
    }
    /* Close the opened dir. */
    closedir(dir_ptr);
}
                
/*
 * Linked list creation. The list holds the full path way of the files.
 * The function takes file name and the pointer to a pointer as arguments.
 * Pointer to pointer used because the value of *paths pointer should be changed globally.
 * Namely we pass the *paths pointer not the paths structure by reference.
 */
void addToPathList(char file_name[], path_list **paths)
{
    if (*paths != NULL) {
        path_list *temp = *paths;
        while ( temp->next != NULL ) {
            temp = temp->next;
        }
        temp->next = (path_list *)malloc(sizeof(path_list));
        if (temp->next == NULL) {
            printf("\n[ERROR] %s\n", strerror(errno));
            exit(errno);
        }
        temp = temp->next;
        temp->next = NULL;
        /* realpath function writes the full path way of the file into temp->path variable */
        if ( realpath(file_name, temp->path) == NULL ) {
            printf("\n%s\n", strerror(errno));
            exit(errno);
        }
    } else if ( *paths == NULL ) {
        *paths = (path_list *)malloc(sizeof(path_list));
        if (*paths == NULL) {
            printf("\n[ERROR] %s", strerror(errno));
            exit(errno);
        }
        (*paths)->next = NULL;
        if ( realpath(file_name, (*paths)->path) == NULL ) {
            printf("\n%s\n", strerror(errno));
            exit(errno);
        }
    }
        
}

/*
 * This function redesign the path list, find an offset for eliminate
 * the common dir names in the all paths. Than remove the duplicate paths.
 */
uint32_t redesignPathList(path_list **paths)
{
    /*
     * Find an offset to eliminate the common root path of all the paths.
     */
    char search[PATH_MAX];
    uint32_t offset = 0;
    uint32_t offset_check = 0;
    char *strchr_ret;
    while (true) {
        path_list *temp = *paths;
        /* 
         * First member checked, until either the parent dir of the member or
         * the common parent dir of all paths.
         */
        if ( (strchr_ret = strchr(temp->path + offset_check + 1, '/')) == NULL ) {
            break;
        }
        offset_check = strchr_ret - temp->path;
        strncpy(search, temp->path, offset_check);
        while (temp->next != NULL) {
            temp = temp->next;
            if (memcmp(search, temp->path, offset_check) != 0) {
                break;
            }
        }
        if (memcmp(search, temp->path, offset_check) != 0) {
            break;
        }
        offset = offset_check;
    }

    /*
     * Remove duplicate files from the heap.
     */
    {
        path_list *temp = *paths;
        while (temp->next != NULL) {
            path_list *check = temp->next;
            path_list *prev = temp;
            while (check->next != NULL) {
                if (strcmp(temp->path + offset, check->path + offset) == 0) {
                    prev->next = check->next;
                    free(check);
                    check = prev->next;
                    continue;
                }
                prev = check;
                check = check->next;
            }
            if (strcmp(temp->path + offset, check->path + offset) == 0) {
                prev->next = check->next;
                free(check);
            }
            temp = temp->next;
            if (temp == NULL) {
                break;
            }
        }
    }
    
    /*
     * Return the offset value to use in info creation and file encryption.
     */
    return offset;
}

/*
 * Multiplication in Galois Field GF(2^8)
 * The code taken from https://en.wikipedia.org/wiki/Rijndael_MixColumns
 */
uint8_t gmul(uint8_t a, uint8_t b)
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

//This is for CBC mode function.
void xor128Bit(uint8_t *const first, uint8_t *const second)
{
    for (uint8_t i = 0 ; i < 16 ; i += sizeof(uint64_t)) {
        *((uint64_t *)(((uint8_t *)first)+i)) ^= *((uint64_t *)(((uint8_t *)second)+i));
    }
}

/*
 * This function splits 256 bit key into biggest chunks supported by the computer arch.
 * Then calculate XOR, if keys are equal than XOR returns 0. Otherwise this means that 
 * keys are not equal and XOR returns non-zero result.
 */
bool compare256BitKeys(const void *const first_key, const void *const second_key)
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
void expan256BitKey(uint8_t expanded_key[][4], const uint8_t *const key)
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
void addRoundKey(uint8_t state[][4], const uint8_t expanded_key[][4], const uint8_t round_num)
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
void createState(uint8_t state[][4], const uint8_t *const block)
{
    for (uint8_t i = 0 ; i < 4 ; i++) {
        for (uint8_t j = 0 ; j < 4 ; j++) {
            state[i][j] = *(block + i + 4*j);
        }
    }
}

void writeOut(uint8_t *const block, uint8_t state[][4])
{
    for (uint8_t i = 0 ; i < 4 ; i++) {
        for (uint8_t j = 0 ; j < 4 ; j++) {
            *(block + i + 4*j) = state[i][j];
        }
    }
}

/*
 * Given data pointer must be able to hold padded data.
 * Ciphered data directly overflow the plain data so
 * in case of that data_size is not multiple of the block_size
 * the padding applied and data size grow little bit.
 */
uint8_t cbcModeEncrypt( uint8_t *const data_ptr,
                        const uintmax_t data_size,
                        uint8_t *const iv_vector,
                        const uint8_t *const cipher)
{
    if ((iv_vector == NULL) || 
        (data_ptr == NULL) ||
        (data_size == 0)) {
        return 1;
    }

    if ( data_size % 16 != 0 ) {
        uint8_t padding_size = 0;
        padding_size = 16 - (data_size % 16);
        for (uint8_t i = 0 ; i < padding_size ; i++) {
            *(data_ptr + data_size + i) = padding_size;
        }
    }

    xor128Bit(data_ptr, iv_vector);
    aes256Encrypt(data_ptr, cipher);
    progressBar(16, NULL);
    for (uintmax_t i = 16 ; i < data_size ; i += 16) {
        xor128Bit((data_ptr + i), (data_ptr + i - 16));
        aes256Encrypt((data_ptr + i), cipher);
        progressBar(16, NULL);
    }
    return 0;
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
void subBytes(uint8_t state[][4])
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
void shiftRows(uint8_t state[][4])
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
void mixCols(uint8_t state[][4])
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
 * This will the reverse of the cbcModeEncrypt
 * Just addition is this cleaning padding bytes.
 */
uint8_t cbcModeDecrypt(uint8_t *data_ptr,
                    const uint64_t data_size,
                    uint8_t *const iv_vector,
                    const uint8_t *const cipher)
{
    if ((iv_vector == NULL) || 
        (data_ptr == NULL) ||
        (data_size == 0)) {
        return 1;
    }

    if ( data_size % 16 != 0 ) {
        printf("\n[ERROR] File could not be decrypted\n");
        exit(1);
    }

    for (uintmax_t i = (data_size - 16) ; i >= 16 ; i -= 16) {
        aes256Decrypt((data_ptr + i), cipher);
        xor128Bit((data_ptr + i), (data_ptr + i - 16));
        progressBar(16, NULL);
    }
    aes256Decrypt(data_ptr, cipher);
    xor128Bit(data_ptr, iv_vector);
    progressBar(16, NULL);
    uint8_t padding_check = *(data_ptr + data_size - 1);
    if ( (padding_check != 0) && (padding_check <= 16) ) {
        uint8_t pad[16];
        memset(pad + sizeof(pad) - padding_check, padding_check, padding_check);
        if (memcmp(data_ptr + data_size - padding_check, pad + sizeof(pad) - padding_check, padding_check) == 0) {
            memset(data_ptr + data_size - padding_check, '\0', padding_check);
        }
    }
    return 0;
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
void inv_subBytes(uint8_t state[][4])
{
    for (uint8_t i = 0 ; i < 4 ; i++) {
        for (uint8_t j = 0 ; j < 4 ; j++) {
            state[i][j] = inv_s_box[state[i][j]];

        }
    }
}

//Cyclically shift to the right.
//Same count with shiftRows.
void inv_shiftRows(uint8_t state[][4])
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
void inv_mixCols(uint8_t state[][4])
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
