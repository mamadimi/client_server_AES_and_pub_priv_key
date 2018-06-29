/**
 * Aristotle Univeristy of Thessaloniki
 * Faculty of engineering.
 * Department of electrical & computer engineering.
 * 
 * Common functions between client and server. 
 * 
 * @author Mamagiannos Dimitrios (7719)
 * @date January 2016
 * 
 * @version 1
 * 
 * gcc -fPIC -c rsacommons.c
 */
#include "rsacommons.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>

#define RSA_BITS 1024
#define PADDING RSA_PKCS1_PADDING

// gcc -fPIC -c rsacommons.c

/**
 * Generate RSA key pair
 * @see https://www.openssl.org/docs/manmaster/crypto/RSA_generate_key.html
 * 
 * @param private_key The private key in string form.
 * @param public_key The public key in string form.
 * @return void
 */

void create_RSA_pair(char *private_key, char *public_key) {
    int key_len;
    char * private_key_tmp;

    RSA *rsa = RSA_generate_key(RSA_BITS, RSA_F4, 0, 0);

    /* To get the C-string PEM form: */
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

    key_len = BIO_pending(bio);
    private_key_tmp = calloc(key_len + 1, 1); /* Null-terminate */
    BIO_read(bio, private_key_tmp, key_len);
    BIO_free(bio);

    int length = (int)(strlen(private_key_tmp));

    int i = 0;
    for (i=0; i<length; i++){
        private_key[i] = private_key_tmp[i];
    }

    char *public_key_tmp;

    /* To get the C-string PEM form: */
    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, rsa);

    key_len = BIO_pending(bio);
    public_key_tmp = calloc(key_len + 1, 1); /* Null-terminate */
    BIO_read(bio, public_key_tmp, key_len);
    BIO_free(bio);

    length = (int)(strlen(public_key_tmp));

    for (i=0; i<length; i++){
        public_key[i] = public_key_tmp[i];
    }
}

/**
 * Create RSA struct
 * 
 * @param key unsigned char * : public or private key
 * @param is_public if(public) then read public key. Else read private key
 * @return RSA struct pointer
 */

RSA *create_RSA(unsigned char *key, int is_public) {
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL) {
        printf( "Failed to create key BIO");
        return 0;
    }
    if (is_public) {
        rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa,NULL, NULL);
    } else {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }

    if(rsa == NULL) {
        printf( "Failed to create RSA");
    }

    BIO_free(keybio);
    return rsa;
}

/**
 * Return size of RSA struct
 * 
 * @param key unsigned char * : public or private key
 * @param is_public 
 * @return RSA size 
 */

int RSA_size_from(unsigned char *key,int is_public) {
    RSA * rsa = create_RSA(key, is_public);
    int sz = RSA_size(rsa);
    RSA_free(rsa);
    return sz;
}
/**
 * Encrypt data using public key
 * 
 * @param src Data foe encrytpion
 * @param len Size of data
 * @param key The publiv key in string form.
 * @param dst The decrypted data.
 * @return size of decrypted data.
 */


int public_encrypt(unsigned char * src, int len, unsigned char * key, unsigned char *dst) {
    RSA * rsa = create_RSA(key, 1);
    return RSA_public_encrypt(len, src, dst, rsa, PADDING);
}

/**
 * Decrypt data using private key
 * 
 * @param enc_data The encrypted data
 * @param data_len Size of encrypted data
 * @param key The private key in string form.
 * @param decrypted The decrypted data.
 * @return size of decrypted data.
 */

int private_decrypt(unsigned char * src, int len, unsigned char * key, unsigned char * dst) {
    RSA * rsa = create_RSA(key, 0);
    return RSA_private_decrypt(len, src, dst, rsa, PADDING);
}
/*
unsigned short crc16(unsigned char* data_p, unsigned char length) {
    unsigned char x;
    unsigned short crc = 0xFFFF;

    while (length--){
        x = crc >> 8 ^ *data_p++;
        x ^= x>>4;
        crc = (crc << 8) ^ ((unsigned short)(x << 12)) ^ ((unsigned short)(x <<5)) ^ ((unsigned short)x);
    }
    return crc;
}

void print_hex(unsigned char* data, unsigned int len) {
    int i;
    for (i = 0; i < len; i++) {
        if (i > 0) printf(":");
        printf("%02X", data[i]);
    }

    printf("\n");
}
*/
