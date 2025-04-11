#include "des.h"
#include <getopt.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#endif

void error_handler(const char *message) {
	fprintf(stderr, "[ERROR] %s\n", message);
	exit(EXIT_FAILURE);
}
void print_usage() {
    printf("Usage: ./DES [-e | -d] -k <key> [-x <hex> | -m <message> | -f <file>] [-o <output>] [-h] [-v]\n");
    printf("Options:\n");
    printf("  -e            Encrypt the input (message, file or 64-bit hex number).\n");
    printf("  -d            Decrypt the input (message, file or 64-bit hex number).\n");
    printf("  -k <key>      Specify the encryption/decryption key (required).\n");
	printf("  -x <hex>      Specify the hex number to encrypt or decrypt.\n");
    printf("  -m <message>  Specify the message to encrypt or decrypt.\n");
    printf("  -f <file>     Specify the file to encrypt or decrypt.\n");
	printf("  -o <output>   Specify the output file for encrypted/decrypted data, default STDOUT.\n");
    printf("  -h            Display this help message.\n");
    printf("  -v            Enable verbose mode for detailed output.\n");
    printf("\n");
    printf("Examples:\n");
    printf("  ./DES -e -k 0x12345678 -x 0x789abc -v\n");
    printf("  ./DES -e -k 0x12345678 -m \"Hello, World!\"\n");
    printf("  ./DES -e -k 0x12345678 -f file.txt -o encrypted_file.txt\n");
    printf("  ./DES -d -k 0x12345678 -f encrypted_file.txt -o decrypted_file.txt\n");
}

int is_valid_command(int encrypt_flag, int decrypt_flag,
					uint64_t key, uint64_t hex, char *message, FILE *fp) {
	if(encrypt_flag && decrypt_flag){
		error_handler( "Cannot specify both -e and -d options.\n");
	}
	if(!encrypt_flag && !decrypt_flag){
		error_handler( "Must specify either -e or -d option.\n");
	}
	if(key == 0){
		error_handler( "Key is required.\n");
	}
	if(message == NULL && fp == NULL && hex == 0){
		error_handler( "Must specify either -x, -m or -f option.\n");
	}
	if(message != NULL && fp != NULL && hex != 0){
		error_handler( "Cannot specify -x, -m and -f options together.\n");
	}
	return 1;
}

int encrypt_flag = 0,decrypt_flag = 0;
uint64_t key = 0;
uint64_t hex = 0;
FILE *fp = NULL;
FILE *out = NULL;
char *message = NULL;
int verbose = 0;

int main(int argc, char *argv[]) {
#ifdef _WIN32
	_setmode(_fileno(stdout), _O_BINARY);
#endif

// 计算程序运行耗时
struct timespec start, end;
double elapsed;

	int opt;
	out = stdout;
	while ((opt = getopt(argc, argv, "edk:x:m:f:o:hv")) != -1) {
		switch (opt) {
			case 'e':
				// Encrypt
				encrypt_flag = 1;
				break;
			case 'd':
				// Decrypt
				decrypt_flag = 1;
				break;
			case 'k':
				// Key
				if (sscanf(optarg, "%llx", &key) != 1) {
					fprintf(stderr, "Invalid key format. Key must be a 64-bit number.\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 'x':
				// Hex message
				if(sscanf(optarg, "%llx", &hex) != 1){
					error_handler("Invalid hex format. Hex must be a 64-bit number.\n");
				}
				break;
			case 'm':
				// Message
				message = malloc(264*sizeof(char));
				if(!message){
					error_handler("Memory allocation failed.\n");
				}
				if(strlen(optarg) > 256){
					error_handler("Message too long. Maximum length is 256 characters.\n");
				}
				strcpy(message, optarg);
				break;
			case 'f':
				// File
				fp = fopen(optarg, "rb");
				if(!fp) {
					error_handler("Failed to open input file.\n");
				}
				break;
			case 'o':
				// Output file
				out = fopen(optarg, "wb");
				if(!out) {
					error_handler("Failed to open output file.\n");
				}
				break;
			case 'h':
				// Help
				print_usage();
				return 0;
			case 'v':
				// Verbose
				verbose = 1;
				break;
			default:
				printf("Usage: ./des [-e | -d] -k <key> [-x <hex> | -m <message> | -f <file>] [-h] [-v]\n");
				exit(EXIT_FAILURE);
		}
	}
	if(is_valid_command(encrypt_flag, decrypt_flag, key, hex, message, fp)){
		if(verbose){
			// 计算程序耗时
			clock_gettime(CLOCK_MONOTONIC, &start);
		}
		uint64_t *plaintext = malloc(sizeof(uint64_t)*BLOCK_NUM);
		uint64_t *ciphertext = malloc(sizeof(uint64_t)*BLOCK_NUM);
		if(plaintext == NULL || ciphertext == NULL){
			fprintf(stderr, "Memory allocation failed.\n");
			exit(EXIT_FAILURE);
		}
		memset((void *)plaintext, 0, BUFF_SIZE);
		memset((void *)ciphertext, 0, BUFF_SIZE);
		init_CDK(key,C,D,K);
		if(encrypt_flag){
		if(fp){
			if(!fp) error_handler("Fail to open file\n");
			encryptFile(fp,plaintext,ciphertext);
			fclose(fp);
			goto RETURN;
		}
		else if(hex){
			plaintext[0] = hex;
			desEncrypt(plaintext,1,ciphertext);
			fprintf(stdout, "%llx", ciphertext[0]);
			goto RETURN;
		}
		else if(message){
			encryptMessage(message,plaintext,ciphertext);
			goto RETURN;
		}
		}
		else if(decrypt_flag){
		if(fp){
			decryptFile(fp,ciphertext,plaintext);
			fclose(fp);
			goto RETURN;
		}
		else if(hex){
			ciphertext[0] = hex;
			desDecrypt(ciphertext,1,plaintext);
			fprintf(stdout, "%016llx", plaintext[0]);
			goto RETURN;
		}
		else if(message){
			decryptMessage(message,ciphertext,plaintext);
			goto RETURN;
		}
		}
		RETURN:
		if(verbose){
			// 输出程序运行时间
			clock_gettime(CLOCK_MONOTONIC, &end);
			elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - 
			start.tv_nsec) / 1e9;
			fprintf(stderr,"[INFO] RUNNING TIME: %f seconds",elapsed);
		}
		return 0;
	}
	exit(EXIT_FAILURE);
}
