#include "aes.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Bảng S-Box
unsigned char sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

// Bảng Rcon
unsigned char Rcon[255] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
    0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
    0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6,
    0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
    0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e,
    0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
    0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
    0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
    0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
    0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb,
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
    0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
    0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb};

unsigned char getSBoxValue(unsigned char num) { return sbox[num]; }
unsigned char getRconValue(unsigned char num) { return Rcon[num]; }

void rotate(unsigned char *word) {
  unsigned char c = word[0];
  for (int i = 0; i < 3; i++)
    word[i] = word[i + 1];
  word[3] = c;
}

void core(unsigned char *word, int iteration) {
  rotate(word);
  for (int i = 0; i < 4; ++i)
    word[i] = getSBoxValue(word[i]);
  word[0] ^= getRconValue(iteration);
}

void expandKey(unsigned char *expandedKey, unsigned char *key,
               enum keySize size, size_t expandedKeySize) {

  int currentSize = 0, rconIteration = 1, i;
  unsigned char t[4] = {0};
  for (i = 0; i < size; i++)
    expandedKey[i] = key[i];
  currentSize += size;
  while (currentSize < expandedKeySize) {
    for (i = 0; i < 4; i++)
      t[i] = expandedKey[(currentSize - 4) + i];
    if (currentSize % size == 0)
      core(t, rconIteration++);
    if (size == SIZE_32 && (currentSize % size) == 16) {
      for (i = 0; i < 4; i++)
        t[i] = getSBoxValue(t[i]);
    }
    for (i = 0; i < 4; i++) {
      expandedKey[currentSize] = expandedKey[currentSize - size] ^ t[i];
      currentSize++;
    }
  }
}

void subBytes(unsigned char *state) {
  for (int i = 0; i < 16; i++)
    state[i] = getSBoxValue(state[i]);
}

void shiftRows(unsigned char *state) {
  for (int i = 0; i < 4; i++)
    shiftRow(state + i * 4, i);
}

void shiftRow(unsigned char *state, unsigned char nbr) {
  for (int i = 0; i < nbr; i++) {
    unsigned char tmp = state[0];
    for (int j = 0; j < 3; j++)
      state[j] = state[j + 1];
    state[3] = tmp;
  }
}

void addRoundKey(unsigned char *state, unsigned char *roundKey) {
  for (int i = 0; i < 16; i++)
    state[i] ^= roundKey[i];
}

unsigned char galois_multiplication(unsigned char a, unsigned char b) {
  unsigned char p = 0, hi_bit_set;
  for (int counter = 0; counter < 8; counter++) {
    if (b & 1)
      p ^= a;
    hi_bit_set = (a & 0x80);
    a <<= 1;
    if (hi_bit_set)
      a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

void mixColumns(unsigned char *state) {
  for (int i = 0; i < 4; i++) {
    unsigned char column[4];
    for (int j = 0; j < 4; j++)
      column[j] = state[(j * 4) + i];
    mixColumn(column);
    for (int j = 0; j < 4; j++)
      state[(j * 4) + i] = column[j];
  }
}

void mixColumn(unsigned char *column) {
  unsigned char cpy[4];
  for (int i = 0; i < 4; i++)
    cpy[i] = column[i];
  column[0] = galois_multiplication(cpy[0], 2) ^
              galois_multiplication(cpy[1], 3) ^ cpy[2] ^ cpy[3];
  column[1] = cpy[0] ^ galois_multiplication(cpy[1], 2) ^
              galois_multiplication(cpy[2], 3) ^ cpy[3];
  column[2] = cpy[0] ^ cpy[1] ^ galois_multiplication(cpy[2], 2) ^
              galois_multiplication(cpy[3], 3);
  column[3] = galois_multiplication(cpy[0], 3) ^ cpy[1] ^ cpy[2] ^
              galois_multiplication(cpy[3], 2);
}

void aes_round(unsigned char *state, unsigned char *roundKey) {
  subBytes(state);
  shiftRows(state);
  mixColumns(state);
  addRoundKey(state, roundKey);
}

void createRoundKey(unsigned char *expandedKey, unsigned char *roundKey) {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++)
      roundKey[(i + (j * 4))] = expandedKey[(i * 4) + j];
  }
}

void aes_main(unsigned char *state, unsigned char *expandedKey, int nbrRounds) {
  unsigned char roundKey[16];
  createRoundKey(expandedKey, roundKey);
  addRoundKey(state, roundKey);
  for (int i = 1; i < nbrRounds; i++) {
    createRoundKey(expandedKey + 16 * i, roundKey);
    aes_round(state, roundKey);
  }
  createRoundKey(expandedKey + 16 * nbrRounds, roundKey);
  subBytes(state);
  shiftRows(state);
  addRoundKey(state, roundKey);
}

char aes_encrypt(unsigned char *input, unsigned char *output,
                 unsigned char *key, enum keySize size) {
  int nbrRounds = (size == SIZE_16) ? 10 : (size == SIZE_24) ? 12 : 14;
  int expandedKeySize = 16 * (nbrRounds + 1);
  unsigned char *expandedKey = (unsigned char *)malloc(expandedKeySize);
  if (!expandedKey)
    return ERROR_MEMORY_ALLOCATION_FAILED;
  unsigned char block[16];
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++)
      block[(i + (j * 4))] = input[(i * 4) + j];
  }
  expandKey(expandedKey, key, size, expandedKeySize);
  aes_main(block, expandedKey, nbrRounds);
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++)
      output[(i * 4) + j] = block[(i + (j * 4))];
  }
  free(expandedKey);
  return SUCCESS;
}
/// Hàm hỗ trợ AES CTR
int generate_nonce(unsigned char *nonce, int len) {
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0)
    return ERROR_FILE_OPERATION_FAILED;
  if (read(fd, nonce, len) != len) {
    close(fd);
    return ERROR_FILE_OPERATION_FAILED;
  }
  close(fd);
  return SUCCESS;
}

void increment_counter(unsigned char *counter) {
  for (int i = 15; i >= 0; i--) {
    if (++counter[i])
      break;
  }
}

void aes_ctr_crypt(unsigned char *input, unsigned char *output, int len,
                   unsigned char *key, unsigned char *nonce,
                   enum keySize size) {
  unsigned char counter[16], keystream[16];
  int i, j;
  memset(counter + 8, 0, 8);
  memcpy(counter, nonce, 8);
  for (i = 0; i < len; i += 16) {
    aes_encrypt(counter, keystream, key, size);
    for (j = 0; j < 16 && (i + j) < len; j++) {
      output[i + j] = input[i + j] ^ keystream[j];
    }
    increment_counter(counter);
  }
}

/// Hàm xử lý dữ liệu

int pad_data(unsigned char *input, unsigned char *padded, int len) {
  int padded_len = ((len / 16) + 1) * 16;
  memcpy(padded, input, len);
  int pad_value = padded_len - len;
  for (int i = len; i < padded_len; i++) {
    padded[i] = (unsigned char)pad_value;
  }
  return padded_len;
}
int unpad_data(unsigned char *data, int len) {
  int pad_value = data[len - 1];
  if (pad_value > 16 || pad_value <= 0)
    return len;
  return len - pad_value;
}

int read_file(const char *filename, unsigned char **data, size_t *len) {
  FILE *file = fopen(filename, "rb");
  if (!file)
    return ERROR_FILE_OPERATION_FAILED;
  fseek(file, 0, SEEK_END);
  *len = ftell(file);
  fseek(file, 0, SEEK_SET);
  *data = (unsigned char *)malloc(*len);
  if (!*data) {
    fclose(file);
    return ERROR_MEMORY_ALLOCATION_FAILED;
  }
  fread(*data, 1, *len, file);
  fclose(file);
  return SUCCESS;
}

int write_file(const char *filename, unsigned char *nonce, unsigned char *data,
               int len) {
  FILE *file = fopen(filename, "wb");
  if (!file)
    return ERROR_FILE_OPERATION_FAILED;
  fwrite(nonce, 1, 8, file);
  fwrite(data, 1, len, file);
  fclose(file);
  return SUCCESS;
}

int write_decrypted_file(const char *filename, unsigned char *data, int len) {
  FILE *file = fopen(filename, "wb");
  if (!file)
    return ERROR_FILE_OPERATION_FAILED;
  fwrite(data, 1, len, file);
  fclose(file);
  return SUCCESS;
}
