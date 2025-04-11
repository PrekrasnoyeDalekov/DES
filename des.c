#include "des.h"

uint32_t C[17] = {0};
uint32_t D[17] = {0};
uint64_t K[17] = {0};
extern uint64_t key;

void desEncrypt(uint64_t *plaintext,size_t blocks,
                uint64_t *ciphertext) {
    // 加密
    for(size_t i = 0;i < blocks;i++){
        ciphertext[i] = encrypt(plaintext[i]);
    }
}

void desDecrypt(uint64_t *ciphertext,size_t blocks,
                uint64_t *plaintext) {
    // 解密
    for(size_t i = 0;i < blocks;i++){
        plaintext[i] = decrypt(ciphertext[i]);
    }
}

void encryptFile(FILE *fp,uint64_t plaintext[BLOCK_NUM],
                 uint64_t ciphertext[BLOCK_NUM]) {
    size_t read_bytes = 0;
    int i = 0;
    while ((read_bytes = fread((void *)plaintext,sizeof(uint8_t),BUFF_SIZE,fp)) == BUFF_SIZE){
        desEncrypt(plaintext,BLOCK_NUM,ciphertext);
        for(size_t i = 0;i < BLOCK_NUM;i++){
            fprintf(out, "%016llx", ciphertext[i]);
        }
    }

    // PKCS7填充
    int to_fill = sizeof(uint64_t)-read_bytes%sizeof(uint64_t); // 要填充的字节数
    size_t blocks = (read_bytes+to_fill)/sizeof(uint64_t); // 填充后有多少blocks
    memset(((void *)plaintext+read_bytes),to_fill,to_fill);
    desEncrypt(plaintext,blocks,ciphertext);
    for(size_t i = 0;i < blocks;i++){
        fprintf(out, "%016llx", ciphertext[i]);
    }
    if(verbose){
        fprintf(stderr,"[INFO] PKCS7 TO_FILL %d B\n",to_fill);
        fprintf(stderr, "[INFO] index: plaintext hex value\n");
        for(int j = 0;j < blocks;j++){
            fprintf(stderr,"[INFO] %5d: %016llx\n",j,plaintext[j]);
        }
    }
}

void decryptFile(FILE *fp,uint64_t ciphertext[BLOCK_NUM],
                 uint64_t plaintext[BLOCK_NUM]) {
    int i = 0;
    char buff[17] = {0};
    while(fgets(buff,17,fp)){
        if(i == BLOCK_NUM){
            desDecrypt(ciphertext,BLOCK_NUM,plaintext);
            fwrite((void *)plaintext,BUFF_SIZE,1,out);
            sscanf(buff,"%llx",&ciphertext[0]);
            i = 1;
            continue;
        }
        sscanf(buff,"%llx",&ciphertext[i]);
        i += 1;
    }
    if(!feof(fp))
        error_handler("The file contains invalid hex\n");

    // 去除PKCS7填充
    if(i){
    desDecrypt(ciphertext,i,plaintext);
    uint8_t to_strip = *(uint8_t *)((void *)&plaintext[i]-1);
    fwrite((void *)plaintext,i*sizeof(uint64_t)-to_strip,1,out);
    if(verbose){
        fprintf(stderr,"[INFO] TO_STRIP %d B\n",to_strip);
        fprintf(stderr,"[INFO] INDEX: PLAINTEXT CHAR\n");
        for(int j = 0;j < i;j++){
            fprintf(stderr,"       %5d: ",j);
            fwrite((void *)&plaintext[j],sizeof(uint64_t),1,stderr);
            fprintf(stderr,"\n");
        }
    }
    }
}

void encryptMessage(const char *message,uint64_t plaintext[BLOCK_NUM],
                  uint64_t ciphertext[BLOCK_NUM]){
    size_t read_bytes = strlen(message)+1;
    memcpy((char *)plaintext,message,read_bytes);
    // PKCS7填充
    size_t to_fill = sizeof(uint64_t)-read_bytes%sizeof(uint64_t); // 要填充的字节数
    memset((void *)plaintext+read_bytes,to_fill,to_fill);
    size_t blocks = (read_bytes+to_fill)/sizeof(uint64_t); // 当前块的索引
    desEncrypt(plaintext,blocks,ciphertext);
    for(int j = 0;j < blocks;j++){
        fprintf(out, "%016llx", ciphertext[j]);
    }
    if(verbose){
        fprintf(stderr,"[INFO] TO_FILL %dB\n",to_fill);
        fprintf(stderr,"[INFO] INDEX: HEX VALUE\n");
        for(int j = 0;j < BLOCK_NUM;j++){
            fprintf(stderr,"       %5d: %016llx\n",j,plaintext[j]);
        }
    }
}
    
void decryptMessage(const char *message,uint64_t plaintext[BLOCK_NUM],
                  uint64_t ciphertext[BLOCK_NUM]){
    if(strlen(message)%16)
        error_handler("The message is not a multiple of 16 bytes\n");
    int i = 0;
    while(1){
    for(i = 0;i < BLOCK_NUM && *message;i++,message+=16){
        if(sscanf(message,"%16llx",&ciphertext[i]) != 1)
            error_handler("The message contains invalid hex\n");
    }
    if(i == BLOCK_NUM){
        desDecrypt(ciphertext,BLOCK_NUM,plaintext);
        uint8_t to_strip = *(uint8_t *)((void *)&plaintext[BLOCK_NUM]+7);
        fwrite((void *)plaintext,BUFF_SIZE,1,out);
        if(verbose){
            fprintf(stderr,"[INFO] TO_STRIP %dB\n",to_strip);
            fprintf(stderr,"[INFO] INDEX: HEX VALUE\n");
            for(int j = 0;j < i;j++){
                fprintf(stderr,"      %5d: ",j);
                fwrite((void *)plaintext+j,sizeof(uint64_t),1,stderr);
                fprintf(stderr,"\n");
            }
        }
    }
    else{
        // 去除PCKS7填充
        desDecrypt(ciphertext,i,plaintext);
        uint8_t to_strip = *(uint8_t *)((void *)&plaintext[i]-1);
        fwrite((void *)plaintext,i*sizeof(uint64_t)-to_strip,1,out);
        if(verbose){
            fprintf(stderr,"[INFO] TO_STRIP %d B\n\n",to_strip);
            fprintf(stderr,"[INFO] INDEX: HEX VALUE\n");
            for(int j = 0;j < i;j++){
                fprintf(stderr,"      %5d: ",j);
                fwrite((void *)plaintext+j,sizeof(uint64_t),1,stderr);
                fprintf(stderr,"\n");
            }
        }
        break;
    }
    }
    return ;
}