#ifndef DES
#define DES

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <time.h>
#include <stdint.h>
 

 
void error_and_exit(char *message);
void create_16_pair_key(char *key_file_addr);
void key_convert_64to48(uint8_t *key);
void key_convert_64to56(int position, uint8_t key_value);
void key_convert_56to48(uint8_t round, int position, uint8_t key_value);
long int find_input_file_size(char *file_name);
void convert_input_file_to_bit(char *file_name, long int block_num);
void convert_char_to_binary(int chararcter, FILE *bit_file);
void encrypt_or_decrypt(long int block_num, int mode);
void block_encryption_decryption(uint8_t *plain_bits, FILE *file);
void initial_permutation(int position, uint8_t bit_value);
void calc_next_right_half(uint8_t round, int mode);
void expansion_message(int position, uint8_t value);
void compress_using_sbox();
uint8_t find_sbox_value(uint8_t gorup_num);
void to_bit(uint8_t value, uint8_t group_num);
void p_box(int position, uint8_t value);
void message_final_permutation(int position, uint8_t value);
int XOR(int a, int b);
void bit_to_char();
void convert_to_char(uint8_t *ch, FILE *plain_text);

#endif