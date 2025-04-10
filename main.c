#include "des.h"
#include <getopt.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

void error_handler(const char *message) {
	fprintf(stderr, "%s\n", message);
	exit(EXIT_FAILURE);
}
void print_usage() {
    printf("Usage: ./des [-e | -d] -k <key> [-x <hex> | -m <message> | -f <file>] [-h] [-v]\n");
    printf("Options:\n");
    printf("  -e            Encrypt the input (either message or file).\n");
    printf("  -d            Decrypt the input (either message or file).\n");
    printf("  -k <key>      Specify the encryption/decryption key (required).\n");
	printf("  -x <hex>      Specify the hex number to encrypt or decrypt.\n");
    printf("  -m <message>  Specify the message to encrypt or decrypt.\n");
    printf("  -f <file>     Specify the file to encrypt or decrypt.\n");
    printf("  -h            Display this help message.\n");
    printf("  -v            Enable verbose mode for detailed output.\n");
    printf("\n");
    printf("Examples:\n");
    printf("  ./des -e -k 0x12345678 -x 0x789abc\n");
    printf("  ./des -e -k 0x12345678 -m \"Hello, World!\"\n");
    printf("  ./des -d -k 0x12345678 -f encrypted_file.txt\n");
}

int is_valid_command(int encrypt_flag, int decrypt_flag,
					uint64_t key, uint64_t hex, char *message, char *file_name) {
	if(encrypt_flag && decrypt_flag){
		error_handler( "Cannot specify both -e and -d options.\n");
	}
	if(!encrypt_flag && !decrypt_flag){
		error_handler( "Must specify either -e or -d option.\n");
	}
	if(key == 0){
		error_handler( "Key is required.\n");
	}
	if(message == NULL && file_name == NULL && hex == 0){
		error_handler( "Must specify either -x, -m or -f option.\n");
	}
	if(message != NULL && file_name != NULL && hex != 0){
		error_handler( "Cannot specify -x, -m and -f options together.\n");
	}
	return 1;
}

int encrypt_flag = 0,decrypt_flag = 0;
uint64_t key = 0;
uint64_t hex = 0;
char *message = NULL;
char *file_name = NULL;
int verbose = 0;

int main(int argc, char *argv[]) {
#ifdef _WIN32
	_setmode(_fileno(stdout), _O_BINARY);
#endif

	int opt;
	while ((opt = getopt(argc, argv, "edk:x:m:f:hv")) != -1) {
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
				if(strlen(optarg) > 255){
					error_handler("File name too long. Maximum length is 256 characters.\n");
				}
				file_name = malloc(256*sizeof(char));
				if(!file_name){
					error_handler("Memory allocation failed.\n");
				}
				strcpy(file_name, optarg);
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
	if(is_valid_command(encrypt_flag, decrypt_flag, key, hex, message, file_name)){
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
		if(file_name){
			FILE *fp = fopen(file_name, "rb");
			if(!fp) error_handler("Error opening file\n");
			encryptFile(fp,plaintext,ciphertext);
			fclose(fp);
			return 0;
		}
		else if(hex){
			plaintext[0] = hex;
			desEncrypt(plaintext,1,ciphertext);
			fprintf(stdout, "%llx", ciphertext[0]);
			return 0;
		}
		else if(message){
			encryptMessage(message,plaintext,ciphertext);
			return 0;
		}
		}
		else if(decrypt_flag){
		if(file_name){
			FILE *fp = fopen(file_name, "rb");
			if(!fp) error_handler("Error opening file\n");
			decryptFile(fp,ciphertext,plaintext);
			fclose(fp);
			return 0;
		}
		else if(hex){
			ciphertext[0] = hex;
			desDecrypt(ciphertext,1,plaintext);
			fprintf(stdout, "%016llx", plaintext[0]);
			return 0;
		}
		else if(message){
			decryptMessage(message,ciphertext,plaintext);
			return 0;
		}
		}
	}
	
	return 0;
}
