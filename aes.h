#ifndef AES_H
#define AES_H

#include <stddef.h>

// Mã lỗi
enum errorCode {
  SUCCESS = 0,
  ERROR_AES_UNKNOWN_KEYSIZE,
  ERROR_MEMORY_ALLOCATION_FAILED,
  ERROR_FILE_OPERATION_FAILED,
};

// Kích thước khóa
enum keySize { SIZE_16 = 16, SIZE_24 = 24, SIZE_32 = 32 };

// Hàm AES cơ bản
unsigned char getSBoxValue(unsigned char num);
void rotate(unsigned char *word);
unsigned char getRconValue(unsigned char num);
void core(unsigned char *word, int iteration);
void expandKey(unsigned char *expandedKey, unsigned char *key,
               enum keySize size, size_t expandedKeySize);
void subBytes(unsigned char *state);
void shiftRows(unsigned char *state);
void shiftRow(unsigned char *state, unsigned char nbr);
void addRoundKey(unsigned char *state, unsigned char *roundKey);
unsigned char galois_multiplication(unsigned char a, unsigned char b);
void mixColumns(unsigned char *state);
void mixColumn(unsigned char *column);
void aes_round(unsigned char *state, unsigned char *roundKey);
void createRoundKey(unsigned char *expandedKey, unsigned char *roundKey);
void aes_main(unsigned char *state, unsigned char *expandedKey, int nbrRounds);
char aes_encrypt(unsigned char *input, unsigned char *output,
                 unsigned char *key, enum keySize size);

// Hàm hỗ trợ AES-CTR
int generate_nonce(unsigned char *nonce, int len);
void increment_counter(unsigned char *counter);
void aes_ctr_crypt(unsigned char *input, unsigned char *output, int len,
                   unsigned char *key, unsigned char *nonce, enum keySize size);

// Hàm xử lý dữ liệu
int pad_data(unsigned char *input, unsigned char *padded, int len);
int unpad_data(unsigned char *data, int len);
int read_file(const char *filename, unsigned char **data, size_t *len);
int write_file(const char *filename, unsigned char *nonce, unsigned char *data,
               int len);
int write_decrypted_file(const char *filename, unsigned char *data, int len);

#endif // AES_H
