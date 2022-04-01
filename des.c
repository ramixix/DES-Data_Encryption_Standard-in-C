#include "des.h"

// give as mode to cal_next_right_half function, that is used to decrypt of encrypt
#define ENCRYPTION_MODE 0
#define DECRYPTION_MODE 1

// the first key permutation, along permutation, key is transformed from 64-bit key to 56-key.(bits at postions 8, 16, 24, 32, 40, 48, 56, 64 are not included.)
int Key_Initial_Permutation[] = {
    57, 49, 41, 33, 25, 17,  9,
    1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};

// the final permutation on key to generate 48 bits keys.
int Key_Final_Permutation[] = {
    14, 17, 11, 24,  1,  5,
    3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

// first permutation that is performed on plain text before any further operation.
 int Message_Initial_Permutation[] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};
 
// array that we will use to expand the 32 bit right half to 48 bit for futher xor operations.
int Expansion[] = {
    32,  1,  2,  3,  4,  5,
    4,  5,  6,  7,  8,  9,
    8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};
 
// s-box'es that are used to compress expanded right half to 32bit.
int S_box_1[4][16] = {
        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
        0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
        4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
        15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
};
 
int S_box_2[4][16] = {
    15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
    3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
    0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
    13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
};
 
int S_box_3[4][16] = {
    10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
    1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
};
 
int S_box_4[4][16] = {
    7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
    3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
};
 
int S_box_5[4][16] = {
    2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
    4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
};
 
int S_box_6[4][16] = {
    12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
    9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
    4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
};
 
int S_box_7[4][16] = {
    4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
    1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
    6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
};
 
int S_box_8[4][16] = {
    13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
    1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
    7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
    2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
};

// after compressing the text using s-box'es you perform another permutation right half to generate P-box 
int P[] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};

// the final permutation on message.
int FP[] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
};
 
// the number of shifts that we perform on each round to generate keys( we perfrom left shift)
uint8_t SHIFTS[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

FILE* out;
uint8_t Key_56bit[56];
uint8_t Key_48bit_array[17][48];
uint8_t Left_half[17][32], Right_half[17][32];    
uint8_t IPtext[64];
uint8_t Expanded_right_half[48];
uint8_t XORtext[48];
uint8_t Compressed_right_half[32];
uint8_t Final_right_half[32];
uint8_t CIPHER[64];
uint8_t ENCRYPTED[64];


//=========================================================================================================================================

// print error message to screen and follow by an error message, and finally finish the program execution.
void error_and_exit(char *message){
    printf("%s\n",message);
    perror("[Error] ");
    exit(1);

}

//=========================================================================================================================================

// read the 64 byte from key file which then translated to an array of 64.
void create_16_pair_key(char *key_file_addr){
    FILE *key_file = fopen(key_file_addr, "rb");
    if(key_file == NULL){
        error_and_exit("Could not open the KEY file.");
    }

    // a list of 64 that will integer value of 0 or 1.
    uint8_t key[64];
    uint8_t iterator=0;
    uint8_t character;

    while( !feof(key_file) ){
        character = getc(key_file);
        key[iterator] = character - 48;
        iterator += 1;
        
    }

    key_convert_64to48(key);
    fclose(key_file);
}

//=========================================================================================================================================

void key_convert_64to48(uint8_t *key){
    uint8_t back_iterator, backup[17][2];
    uint8_t key_left_part[17][28], key_rigth_part[17][28];
    uint8_t key_merged[17][56];

    // permutation and elimination of every 8th bit position
    for (int i = 0; i < 64; i++) {
        key_convert_64to56(i, key[i]);
    }

    // devide the key into two 28bit part.
    for(int i = 0 ; i < 56; i++){
        if( i < 28){
            key_left_part[0][i] = Key_56bit[i];
        }
        else{
            key_rigth_part[0][i - 28] = Key_56bit[i];
        }
    }

    // generating 16 key pair and perform shifting
    for(int k_index = 1; k_index <= 16; k_index++){
        // find the number of bits to shift left every part on the key.
        int shift_num = SHIFTS[k_index - 1];

        // perform left shift up to shift_num number of key_left_part
        // first get the left most bits into backup, because they will be cycle back into right most bits
        for(int shift = 0; shift < shift_num; shift++){
            backup[k_index - 1][shift] = key_left_part[k_index - 1][shift];
        }
        for(int i = 0; i < (28 - shift_num); i++){
            key_left_part[k_index][i] = key_left_part[k_index - 1][i + shift_num];
        }
        back_iterator = 0;
        for(int i = (28 - shift_num); i < 28 ; i++){
            key_left_part[k_index][i] = backup[k_index - 1][back_iterator++];
        }

        // now perform left shift up to shift_num number on key_right_part, similar to left part
        for(int shift = 0; shift < shift_num; shift++){
            backup[k_index - 1][shift] = key_rigth_part[ k_index - 1][shift];
        }
        for(int i = 0; i < (28 - shift_num); i++){
            key_rigth_part[k_index][i] = key_rigth_part[k_index - 1][i + shift_num];
        }
        back_iterator = 0;
        for(int i = (28 - shift_num); i < 28 ; i++){
            key_rigth_part[k_index][i] = backup[k_index - 1][back_iterator++];
        }

    }

    // merging the left and right part after shifting each part.
    for(int k_index = 0; k_index < 17; k_index++){
        for(int i = 0; i < 28; i++){
            key_merged[k_index][i] = key_left_part[k_index][i];
        }

        for(int i = 28; i < 56; i++){
            key_merged[k_index][i] = key_rigth_part[k_index][i - 28];
        }
    }

    // now perform the last permutation on ever 16 shifted keys and generate 48 bit keys.
    for(int k_index = 1; k_index <= 16; k_index++){
        for(int i=0; i < 56; i++){
            key_convert_56to48(k_index, i, key_merged[k_index][i]);
        }
    }
}

//=========================================================================================================================================

void key_convert_64to56(int position, uint8_t key_value){
    uint8_t i;
    for(i = 0; i < 56; i++){
        if(Key_Initial_Permutation[i] == position + 1){
            break;
        }
    }
    if(i != 56){
        Key_56bit[i] = key_value;
    }
}

//=========================================================================================================================================

void key_convert_56to48(uint8_t round, int position, uint8_t key_value){
    uint8_t i;
    for(i = 0; i < 48; i++){
        if(Key_Final_Permutation[i] == position + 1){
            break;
        }
    }
    if(i != 48){
        Key_48bit_array[round][i] = key_value;
    }
}

//=========================================================================================================================================

long int find_input_file_size(char *file_name){
    FILE *input_file = fopen(file_name, "rb");
    long int file_size;

    if(input_file == NULL){
        error_and_exit("Could not open input file.");
    }

    if(fseek(input_file, 0L, SEEK_END)){
        error_and_exit("Could not find the size of file, fseek() failed.");
    }else{
        // ftell return the curser postion, since we set it to the last of the file, it will be equal to size of the file.
        file_size = ftell(input_file);
    }

    fclose(input_file);
    return file_size;
}

//=========================================================================================================================================

void convert_input_file_to_bit(char *file_name, long int block_num){
    FILE *input_file = fopen(file_name, "rb");
    FILE *bit_file = fopen("bits.txt", "wb+");

    char ch;
    long int char_num = block_num * 8;
    
    while(char_num){
        ch = fgetc(input_file);
        if( ch == -1){
            break;
        }
        char_num -= 1;
        convert_char_to_binary(ch, bit_file);
    }

    fclose(input_file);
    fclose(bit_file);

}

//=========================================================================================================================================

void convert_char_to_binary(int chararcter, FILE *bit_file){
    int one_position, is_bit_set;

    for(int shift_num = 7; shift_num >= 0; shift_num--){
        one_position = 1 << shift_num;
        is_bit_set = one_position & chararcter;

        if(is_bit_set){
            fprintf(bit_file, "1");
        }else{
            fprintf(bit_file, "0");
        }
    }
}

//=========================================================================================================================================

void encrypt_or_decrypt(long int block_num, int mode){
    FILE *file;
    if(mode == ENCRYPTION_MODE){
        file = fopen("bits.txt", "rb");
    }
    else{
        char cipher_path[200];
        printf("Enter the path of file that you want to Decrypt: ");
        scanf("%199s", cipher_path);
        file = fopen(cipher_path, "rb");
    }

    uint8_t plain_bits[block_num * 64];
    char ch;
    long int bit_index = 0;

    while(!feof(file)){
        ch = getc(file);
        plain_bits[bit_index] = ch - 48;
        bit_index += 1;
    }
    
    if(mode == ENCRYPTION_MODE){
        char cipher_path[200];
        printf("Where do you want to save the file?(give the absolute path or just enter name to save it in current directory): ");
        scanf("%199s", cipher_path);

        FILE *cipher_file = fopen(cipher_path, "ab+");
        if(cipher_file == NULL){
            error_and_exit("Could not create or append to your specified cipher file.");
        }

        printf("Encrypting the given message...\n");
        for(int block_index = 0; block_index < block_num ; block_index++){
            block_encryption_decryption(&plain_bits[block_index * 64], cipher_file);
        }
        printf("\nEncryption process is done.\nYour file is encrypted successfully!!!!!\n");
        fclose(cipher_file);
    }
    else{
        FILE *decrypt_bit_file = fopen("decrypted.txt", "ab+");
        if(decrypt_bit_file == NULL){
            error_and_exit("Could not create or append to your specified decrypt file.");
        }

        for(int block_index = 0; block_index < block_num ; block_index++){
            block_encryption_decryption(&plain_bits[block_index * 64], decrypt_bit_file);
            bit_to_char();
        }


    }
    

}

//=========================================================================================================================================

void block_encryption_decryption(uint8_t *plain_bits, FILE *file){
   
    // first implement the initial permutation on block
    for(int i = 0; i < 64; i++){
        initial_permutation(i, plain_bits[i]);
    }

    // devide the block into 32 left and right parts.
    for(int i = 0; i < 32; i++){
        Left_half[0][i] = IPtext[i];
    }
    for(int i = 32; i < 64; i++){
        Right_half[0][i - 32] = IPtext[i];
    }

    // now perform the main operation of left part and right part of block
    // in each round the left half of next block will be the right half of current block
    // and the right half of next block will follow : (Right half current block ^xor current key) ^xor left half of current block
    for(int round = 1; round <= 16; round++){
        calc_next_right_half(round, ENCRYPTION_MODE);
        for(int i = 0; i < 32; i++){
            Left_half[round][i] = Right_half[round - 1][i];
        }
    }

    // join the left and right half of the last round is our cipher text.
    // be careful that we at end we swap them. (right comes first then left comes after that.)
    // that is because, in our first round the current right half became the next left half. 
    // and by doing this in each round, at round 16, the last left half and right half are not placed in right place.
    for(int i = 0; i < 64; i++){
        if(i < 32){
            CIPHER[i] = Right_half[16][i];
        }else{
            CIPHER[i] = Left_half[16][i - 32];
        }
    }
    
    // now we perform the last permutation and write the final encrypted message to our cipher.txt
    for(int i = 0; i < 64; i++){
        message_final_permutation(i, CIPHER[i]);   
    }
    
    for (int i = 0; i < 64; i++) {
        fprintf(file, "%d", ENCRYPTED[i]);
    }
   
}

//=========================================================================================================================================

void initial_permutation(int position, uint8_t bit_value){
    int i;
    for( i = 0 ; i < 64; i++){
        if(Message_Initial_Permutation[i] == position + 1){
            break;
        }
    }
    IPtext[i] = bit_value;

}

//=========================================================================================================================================

void calc_next_right_half(uint8_t round, int mode){
    // expand the message from 32 bit to 48 bit. so we can perform xor operation with 48 bit key.
    for(int i = 0; i < 32; i++){
        expansion_message(i, Right_half[round - 1][i]);
    }
  
    // perform xor operation on expanded right half and key.
    // in decryption mode the xor operation start from last to first.
    for(int i = 0; i < 48; i++){
        if(mode == ENCRYPTION_MODE){
            XORtext[i] = XOR(Expanded_right_half[i], Key_48bit_array[round][i]);
        }else{
            XORtext[i] = XOR(Expanded_right_half[i], Key_48bit_array[17 - round][i]);
        }
    }

    // compress the 48 bit message again to 32 bit using s-box'es.
    compress_using_sbox();

    // perform permutation on righ half and generate P-box.
    for(int i = 0 ; i < 32; i++){
        p_box(i, Compressed_right_half[i]);
    }

    for(int i = 0; i < 32; i++){
        Right_half[round][i] = XOR(Final_right_half[i], Left_half[round - 1][i]);
    }
    
}

//=========================================================================================================================================

void expansion_message(int position, uint8_t value){
    for(int i =0; i < 48; i++){
        if(Expansion[i] == position + 1){
            Expanded_right_half[i] = value;
        }
    }
}

//=========================================================================================================================================

void compress_using_sbox(){
    // we expanded 32bit to 48bit. we done this by dividing 32bit into 8 groups of 4bit and add 2bit to each group.
    // So now we have 8 groups of 6bit.
    // here we again want to compress each group 4 bit again. To do this we use S-box'es. at end we'll have 8 goups of 4bit.
    uint8_t value;
    for(uint8_t group_num = 0; group_num < 8; group_num++){
        value = find_sbox_value(group_num);
        to_bit(value, group_num);
    }
}
//=========================================================================================================================================

uint8_t find_sbox_value(uint8_t group_num){
    uint8_t row, column;
    uint8_t six_bits[6];
    for(int i = 0; i < 6; i++){
        six_bits[i] = XORtext[group_num * 6 + i];
    }

    // from 6bits in each group, we take the first and last to find row and the rest is used to find column postion.
    // row variable is 2 bits therefore it's value is between 0-3 (00, 01, 10, 11).
    // column variable is 4 bits therefore it's value is between 0-15 (0000, 0001, 0010, 0011, 0100, ...).
    row = six_bits[0] * 2 + six_bits[5];
    column = six_bits[1] * 8 + six_bits[2] * 4 + six_bits[3] * 2 + six_bits[4];
    
    switch (group_num)
    {
    case 0:
        return S_box_1[row][column];
        break;
    case 1:
        return S_box_2[row][column];
        break;
    case 2:
        return S_box_3[row][column];
        break;
    case 3:
        return S_box_4[row][column];
        break;
    case 4:
        return S_box_5[row][column];
        break;
    case 5:
        return S_box_6[row][column];
        break;
    case 6:
        return S_box_7[row][column];
        break;
    case 7:
        return S_box_8[row][column];
        break;
    default:
        break;
    }

}

//=========================================================================================================================================

void to_bit(uint8_t value, uint8_t group_num){
    int one_position, is_bit_set;

    for(int shift_num = 3; shift_num >= 0; shift_num--){
        one_position = 1 << shift_num;
        is_bit_set = one_position & value;

        if(is_bit_set){
            Compressed_right_half[3 - shift_num + (group_num * 4) ] = '1' - 48;
        }else{
            Compressed_right_half[3 - shift_num + (group_num * 4) ] = '0' - 48;
        }
    }
}

//=========================================================================================================================================

void p_box(int position, uint8_t value){
    int i;
    for(i = 0; i < 32; i++){
        if(P[i] == position + 1){
            break;
        }
    }
    Final_right_half[i] = value;
}

//=========================================================================================================================================

void message_final_permutation(int position, uint8_t value){
    int i;
    for(i = 0; i < 64; i++){
        if(FP[i] == position + 1){
            break;
        }
    }
    ENCRYPTED[i] = value;
}

//=========================================================================================================================================

int XOR(int a, int b) {
    return (a ^ b);
} 

//=========================================================================================================================================

void bit_to_char(){
    FILE *plain_text = fopen("result.txt", "ab+");
    for (int i = 0; i < 64; i = i + 8) {
        convert_to_char(&ENCRYPTED[i], plain_text);
    }
    fclose(plain_text);
}

//=========================================================================================================================================

void convert_to_char(uint8_t *ch, FILE *plain_text){
    int value = 0;
    for(int i = 7; i >= 0; i++){
        value += (int)pow(2, i) * ch[7 - i];
    }
    fprintf(plain_text, "%c", value);
}

//=========================================================================================================================================

//=========================================================================================================================================

//=========================================================================================================================================