#ifndef DES_H
#define DES_H
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cipherkey.h"
#include "encrypt.h"
#include "decrypt.h"
#define BLOCK_NUM 32
#define BUFF_SIZE sizeof(uint64_t) * BLOCK_NUM

extern uint32_t C[17];
extern uint32_t D[17];
extern uint64_t K[17];
extern uint64_t key;
extern FILE *out;

// void encrypt(uint8_t *data, uint8_t *key);
// void decrypt(uint8_t *data, uint8_t *key);
extern int verbose;
void init_CDK(uint64_t key64,uint32_t C[17],
                uint32_t D[17],uint64_t K[17]);
void desEncrypt(uint64_t *plaintext,size_t blocks,
                 uint64_t *ciphertext);
void desDecrypt(uint64_t *ciphertext,size_t blocks,
                uint64_t *plaintext);
void error_handler(const char *msg);
void encryptFile(FILE *fp,uint64_t plaintext[BLOCK_NUM],
                 uint64_t ciphertext[BLOCK_NUM]);
void decryptFile(FILE *fp,uint64_t ciphertext[BLOCK_NUM],
                 uint64_t plaintext[BLOCK_NUM]);
void encryptMessage(const char* message, uint64_t plaintext[BLOCK_NUM],
                 uint64_t ciphertext[BLOCK_NUM]);
void decryptMessage(const char* message, uint64_t ciphertext[BLOCK_NUM],
                 uint64_t plaintext[BLOCK_NUM]);

#endif
