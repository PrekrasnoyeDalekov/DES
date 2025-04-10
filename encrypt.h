#ifndef ENCRYPT_H
#define ENCRYPT_H
#include "des.h"

extern const uint8_t IP[64];
extern const uint8_t IP_1[64];
extern const uint8_t E[48];
extern const uint8_t S[8][64];
extern const uint8_t P[32];
uint64_t encrypt(uint64_t plaintext);
uint32_t feistel(uint32_t R, uint64_t Ki);
uint32_t Subsitute(uint64_t extendedR);

#endif
