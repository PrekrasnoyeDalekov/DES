#include "des.h"

const uint8_t PC_1[56] = {
	57, 49, 41, 33, 25, 17,  9,
	1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27,
	19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29,
	21, 13,  5, 28, 20, 12,  4
};

const uint8_t shift[16] = {
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

const uint8_t PC_2[48] = {
	14, 17, 11, 24,  1,  5,
	3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8,
	16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};


uint64_t get_key56(uint64_t key64){
    uint64_t key56 = 0;
    uint64_t bit = 0;
    for (int i = 0; i < 56; i++){
        bit = (key64 >> (64 - PC_1[i])) & 0x1;
        key56 |= (bit << (55 - i));
    }
    return key56;
}


void fill_CDK(uint64_t key64,uint32_t C[17],uint32_t D[17],uint64_t K[17]){
    uint64_t key56 = get_key56(key64);
    uint64_t bit = 0;
    C[0] = (key56 >> 28) & 0xFFFFFFF;
    D[0] = key56 & 0xFFFFFFF;
    for (int i = 1;i < 17;i++){
        C[i] = C[i-1] << shift[i-1];
        C[i] |= C[i-1] >> (28 - shift[i-1]);
        C[i] &= 0xFFFFFFF;
        D[i] = D[i-1] << shift[i-1];
        D[i] |= D[i-1] >> (28 - shift[i-1]);
        D[i] &= 0xFFFFFFF;
    }
    for(int i = 1;i < 17; i++){
        uint64_t k56i = ((uint64_t)C[i] << 28) | D[i];
        uint64_t k48i = 0;
        for(int j = 0;j < 48;j++){
            bit = (k56i >> (56 - PC_2[j])) & 0x1;
            k48i |= (bit << (47 - j));
        }
        K[i] = k48i;
    }
}
// 至此,通过调用fill_CDK函数,我们就能完成16个48位子密钥的生成

