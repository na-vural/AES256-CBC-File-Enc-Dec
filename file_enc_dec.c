#include <linux/limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h> //bool
#include <errno.h> //errno
#include <dirent.h> //readdir opendir
#include <unistd.h> //getcwd chdir
#include <time.h>
#include <sys/stat.h>
#include "aes256.h"

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
void xor128Bit(uint8_t *const first, uint8_t *const second); //XOR second data into first data. For CBC mode.
/* Function declarations about AES256 CBC MODE Encrypt */
uint8_t cbcModeEncrypt( uint8_t *const data_ptr,
                        const uint64_t data_size,
                        uint8_t *const iv_vector,
                        const uint8_t *const cipher);
void aes256Encrypt(uint8_t *const block,
                   const uint8_t *const cipher);
/* Function declarations about AES256 CBC MODE Decrypt */
uint8_t cbcModeDecrypt(uint8_t *const data_ptr,
                    const uint64_t data_size,
                    uint8_t *const iv_vector,
                    const uint8_t *const cipher);
void aes256Decrypt(uint8_t *const block,
                   const uint8_t *const cipher);

/***************** MAIN AND FUNCTIONS *****************/

int main(int argc, char *argv[]) {
    //Begin time save, srand for random data, setvbuf for stdout buffer size.
    /* Time calculation will be changed.
    time_t exec_begin, exec_end;
    exec_begin = time(NULL);
    */
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
    /* Time calculation will be changed.
    //Finish, total time calculation and print the total time
    exec_end = time(NULL);
    printf("in %ld second.\n", exec_end - exec_begin);
    */

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
            printf("\n[ERROR] %d\n%s: %s\n", errno, file, strerror(errno));
            exit(errno);
        }
        if ( (check.st_mode & S_IFMT) != S_IFREG ) {
            printf("\n[ERROR] %d\n%s: %s\n", errno, file, "It is not a regular file.");
            exit(1);
        }
        decryption_size = check.st_size;
    }
    //Open the encrypted file
    FILE *fin;
    char file_id_check[sizeof(file_id)];
    if ( (fin = fopen(file, "rb")) == NULL ) {
        printf("\n[ERROR] %d\n%s: %s\n", errno, file, strerror(errno));
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
            printf("\n[ERROR] %d: %s\n", errno, strerror(errno));
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
        //overwrite check
        if ( lstat(file_name, &check) == 0 ) {
            if ( (check.st_mode & S_IFMT) == S_IFREG ) {
                printf("\"%s\" is exist, do you want to overwrite?%-69s\n[y/N] -> ", dec_data_ptr, " ");
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
        //opening the decrypted file
        if ( (fout = fopen(file_name, "wb")) == NULL ) {
            if ( errno != ETXTBSY ) { //If file is busy, than we pass it.
                printf("\n[ERROR] %d\n%s: %s\n", errno, file_name, strerror(errno));
                fclose(fin);
                exit(errno);
            } else if ( errno == ETXTBSY ) { //If file is busy, program continues to execution.
                printf("\n[ERROR] %d\n%s: %s\n\n", errno, file_name, strerror(errno));
                continue;
            }
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
                    printf("\n[ERROR] %d: %s\n", errno, strerror(errno));
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
            printf("\n[ERROR] %d\n%s: %s\n", errno, files[i], strerror(errno));
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
            printf("\n[ERROR] %d\n%s: %s\n", errno, files[i], strerror(errno));
            exit(errno);
        }
        if ( (check.st_mode & S_IFMT) == S_IFREG ) {
            addToPathList(files[i], &paths);
        } else if ( (check.st_mode & S_IFMT) == S_IFDIR ) {
            filesInDir(files[i], &paths);
            if (chdir(base) != 0) {
                printf("\n[ERROR] %d\n%s: %s\n", errno, "..", strerror(errno));
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
                printf("\n[ERROR] %d\n%s: %s\n", errno, temp->path, strerror(errno));
                exit(errno);
            }
            //Files and their paths will be encrypted.
            file_size = (uint64_t)check.st_size + strlen(temp->path + path_offset) + 2; //The "." dot and null char added to the file path.
            file_size += (16 - (file_size % 16)) % 16;
            total_enc_size += file_size;
            break;
        }
        //this section for the temp->next != NULL, same process with above.
        header_size += 1;
        if ( lstat(temp->path, &check) == -1 ) {
            printf("\n[ERROR] %d\n%s: %s\n", errno, temp->path, strerror(errno));
            exit(errno);
        }
        file_size = (uint64_t)check.st_size + strlen(temp->path + path_offset) + 2; //The "." dot and null char added to the file path.
        file_size += (16 - (file_size % 16)) % 16;
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
            printf("\n[ERROR] %d\n%s: %s\n", errno, temp->path, strerror(errno));
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
        data_header.padding_size = (16 - (encrypted_data_size % 16)) % 16;
        //memory pointer for the file that will encrypted.
        data_ptr = (uint8_t *)malloc(encrypted_data_size + data_header.padding_size);
        if (data_ptr == NULL) {
            printf("\n[ERROR] %d: %s\n", errno, strerror(errno));
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
        printf("\n[ERROR] %d\n%s: %s\n", errno, dir, strerror(errno));
        exit(errno);
    }
    
    /* Change active directory to given directory for iterative search. */
    if (chdir(dir) != 0) {
        printf("\n[ERROR] %d\n%s: %s\n", errno, dir, strerror(errno));
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
                printf("\n[ERROR] %d\n%s: %s\n", errno, d_enum->d_name, strerror(errno));
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
                    printf("\n[ERROR] %d\n%s: %s\n", errno, d_enum->d_name, strerror(errno));
                    exit(errno);
                }
                /* Because we changed the current dir, we iterate with "." current dir specifier. */
                filesInDir(".", &(*paths));
                /* After the iteration we back to the parent dir. */
                if (chdir("..") != 0) {
                    printf("\n[ERROR] %d\n%s: %s\n", errno, "..", strerror(errno));
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
            printf("\n[ERROR] %d: %s\n", errno, strerror(errno));
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

//This is for CBC mode function.
void xor128Bit(uint8_t *const first, uint8_t *const second)
{
    for (uint8_t i = 0 ; i < 16 ; i += sizeof(uint64_t)) {
        *((uint64_t *)(((uint8_t *)first)+i)) ^= *((uint64_t *)(((uint8_t *)second)+i));
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
