#include "des.h"
#include <unistd.h>

#define PATH_LENGTH 200
// DES works by encrypting groups of 64 bits message.(8 byte, 16 hexadecimal number). so we can say,
// DES is a block cipher--meaning it operates on plaintext blocks of a given size (64-bits) and returns ciphertext blocks of the same size.
// Each block of 64 bits is divided into two blocks of 32 bits each, a left half block L and a right half R. 

// Plaintext given to DES will be encrypted in block of 8 byes, therefore if a 38 bytes message given to DES
// it will devided to 4 blocks of 8 byte (4*8=32) and a block of 6 byte, but since it should be 8 byte
// the last block must be padded with some extra bytes at the tail end for the encryption.

// DES uses a 64 bits key sizes , However, every 8th key bit is ignored in the DES algorithm, so that the effective key size is 56 bits.
// bits numbered 8, 16, 24, 32, 40, 48, 56, and 64 gets eliminated.

int main(){
    char file_path[PATH_LENGTH];
    char key_path[PATH_LENGTH];
    int choise;

    while(1){
        system("clear");

        printf("\n##############################-=[ Choose A Number ]=-##############################\n");
        printf("1. Encrypt\n\n");
        printf("2. Decrypt\n\n");
        printf("3. Exit\n\n");
        printf("====================================================================================\n\n");
        printf("What operation would you like to perform : ");
        scanf("%d", &choise);

        long int n;
        switch(choise){
            case 1: 
                    printf("Enter the path of your Key file (it must contain 64byte of 0 and 1's): ");
                    scanf("%199s", key_path);
                    printf("Enter the path of file that you want to Encrypt: ");
                    scanf("%199s", file_path);
                    create_16_pair_key(key_path);
                    n = find_input_file_size(file_path) / 8;
                    convert_input_file_to_bit(file_path, n);
                    encrypt_or_decrypt(n, 0);
                    break;
            case 2: 
                    printf("Enter the path of your Key file (it must contain 64byte of 0 and 1's): ");
                    scanf("%199s", key_path);
                    // printf("Enter the path of file that you want to Decrypt: ");
                    // scanf("%199s", file_path);
                    create_16_pair_key(key_path);
                    n = find_input_file_size(file_path) / 8;
                    encrypt_or_decrypt(n, 1);
                
                    break;

            case 3: 
                    exit(0);
                    break;
            default:
                printf("\n[!!!] The number %d is an invalid selection.\n\n", choise);
            }
            sleep(1);
        }
    // create_16_pair_key("hello.txt");
    // long int n = find_input_file_size("input.txt") / 8;
    // convert_input_file_to_bit("input.txt", n);
    // encrypt(n);
    // printf("%d", n);
}

