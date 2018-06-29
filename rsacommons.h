#ifndef RSA_COMMONS_H
#define RSA_COMMONS_H

int RSA_size_from(unsigned char *key,int is_public);
void create_RSA_pair(char *private_key, char *public_key);
int public_encrypt(unsigned char * src, int len, unsigned char * key, unsigned char *dst);
int private_decrypt(unsigned char * src, int len, unsigned char * key, unsigned char * dst);

unsigned short crc16(unsigned char* data_p, unsigned char length);
void print_hex(unsigned char* data, unsigned int len);

#endif RSA_COMMONS_H
