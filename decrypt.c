#include "des.h"

extern uint32_t C[17];
extern uint32_t D[17];
extern uint64_t K[17];


uint64_t decrypt(uint64_t ciphertext){
    uint64_t plantext = 0;
    uint32_t L, R;
    uint32_t tempL, tempR;
    uint64_t bit = 0;

    // 初始置换
    for(int i = 0;i < 64;i++){
        bit = (ciphertext >> (64 - IP[i])) & 1;
        plantext |= (bit << (63 - i));  
    }

    // 分割为L0和R0
    L = (plantext >> 32) & 0xFFFFFFFF;
    R = plantext & 0xFFFFFFFF;

    // 16轮逆Festel网络
    for(int i = 16;i > 0;i--){
        tempL = L;
        tempR = R;
        L = tempR;
        R = tempL ^ feistel(R,K[i]);
    }
    // 最后交换L和R
    uint64_t rawtext = ((uint64_t)R << 32) | (uint64_t)L;

    // 逆初始置换
    plantext = 0;
    for(int i = 0;i < 64;i++){
        bit = (rawtext >> (64 - IP_1[i])) & 0x1;
        plantext |= (bit << (63 - i));
    }
    return plantext;

}
