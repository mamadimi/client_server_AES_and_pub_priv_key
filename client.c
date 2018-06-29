/**
 * Aristotle Univeristy of Thessaloniki
 * Faculty of engineering.
 * Department of electrical & computer engineering.
 * 
 * Client - server communication using a symmetric AES key.
 * Server send the public key to client
 * A random symmetric key is generated and is encrypted in the side of client using server's public key
 * Client sends messages to server
 * 
 * Info about RSA encryption
 * @see https://www.openssl.org/docs/manmaster/crypto/RSA_public_encrypt.html
 * 
 * @author Mamagiannos Dimitrios (7719)
 * @date January 2016
 * 
 * @version 1.2
 * 
 * gcc client.c rsacommons.c -o client -lcrypto -lssl
 */
#include<stdio.h> 
#include<string.h>    
#include<sys/socket.h>   
#include<arpa/inet.h> 
#include "stdlib.h"
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <unistd.h>
#include "rsacommons.h"

#define AES_BITS 128
#define AES_KEY_LEN AES_BITS / 8
#define BUFFER_LEN 1000


/**
 * Print the error that hapenned last.
 * 
 * @return void
 */

void printLastError(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}

/**
 * Main
 */

int main(int argc , char *argv[])
{
    int sock;
    struct sockaddr_in server;
    char message[BUFFER_LEN], server_reply[BUFFER_LEN];

    //Create socket
    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");

    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons( 8888 );

    //Connect to remote server
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("connect failed. Error");
        return 1;
    }

    puts("Connected\n");

    //Receive server's public key

    printf("Receive server's public key\n");

    memset(server_reply, 0, BUFFER_LEN);

    if(recv(sock , server_reply , BUFFER_LEN , 0) < 0)
    {
        puts("recv failed");
    }

    printf("Server's public key is received\n");
    printf("Server public key is :\n");
    printf("%s", server_reply);
    fflush(stdout);

    //Generate an AES_KEY for symmetric encryption
    unsigned char session_key [AES_KEY_LEN];

    AES_KEY enc_key;
    if (!RAND_bytes(session_key, AES_KEY_LEN)) exit(-1);
    AES_set_encrypt_key(session_key, AES_BITS, &enc_key);

    //Encrypt with server's public key
    int encrypted_len = RSA_size_from(server_reply,1);
    unsigned char *session_key_encrypted =
            (unsigned char *) malloc(encrypted_len * sizeof(char));
    memset(session_key_encrypted, 0, encrypted_len);

    int encrypted_length= public_encrypt(session_key, (int)(strlen(session_key)), server_reply, session_key_encrypted);
    if(encrypted_length == -1)
    {
        printLastError("Public Encrypt failed ");
    }


    //Send Encrypted key to server
    if(send(sock, session_key_encrypted, encrypted_len, 0) < 0)
    {
        puts("Send failed");
        return 1;
    }

    //keep communicating with server
    while(1){
        memset(message, 0, sizeof(message));
        printf("\nEnter message : ");
        fflush(stdin);
        scanf("%s" , message);
        unsigned char enc_message[BUFFER_LEN];
        AES_encrypt(message, enc_message, &enc_key);


        printf("Encrypted message is\n%s\n",enc_message);
        fflush(stdout);

        //Send some data

        if( send(sock , enc_message , 1000 , 0) < 0)
        {
            puts("Send failed");
            return 1;
        }

        //Receive a reply from the server
        memset(server_reply, 0, sizeof(server_reply));
        if(recv(sock, server_reply, 2000, 0) < 0)
        {
            puts("recv failed");
            break;
        }

        puts("Server reply :");
        puts(server_reply);
    }

    close(sock);
    return 0;
}
