#ifndef DECRYPT_H
#define DECRYPT_H
#include "des.h"

void init_CDK(uint64_t key64,uint32_t C[17],
                uint32_t D[17],uint64_t K[17]);
uint64_t decrypt(uint64_t ciphertext);
uint32_t feistel(uint32_t R, uint64_t Ki);
uint32_t Subsitute(uint64_t extendedR);

#endif
