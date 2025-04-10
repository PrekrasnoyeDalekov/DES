#ifndef CIPHERKEY_H
#define CIPHERKEY_H
#include "des.h"

extern const uint8_t PC_1[56];
extern const uint8_t shift[16];
extern const uint8_t PC_2[48];

uint64_t get_key56(uint64_t key64);
void fill_CDK(uint64_t key64,uint32_t C[17],uint32_t D[17],uint64_t K[17]); 




#endif
