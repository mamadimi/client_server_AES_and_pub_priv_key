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
 * gcc server.c rsacommons.c -o server -lcrypto -lssl
 */

#include<stdio.h>
#include "stdlib.h"
#include<string.h>    
#include<sys/socket.h>
#include<arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include "rsacommons.h"

#define AES_BITS 128
#define AES_KEY_LEN AES_BITS / 8

#define RSA_LEN 1000
#define BUFFER_LEN 1000

/**
 * Print the error that happened last.
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

    int socket_desc , client_sock , addr_len, read_size;
    struct sockaddr_in server , client;
    char client_message[BUFFER_LEN];

    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");

    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( 8888 );

    //Bind
    if(bind(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        //print the error message
        perror("bind failed. Error");
        return 1;
    }
    puts("bind done");

    //Listen
    listen(socket_desc , 3);

    //Generate RSA key
    char rsa_private_key[RSA_LEN], rsa_public_key[RSA_LEN];
    memset(rsa_private_key, 0, RSA_LEN);
    memset(rsa_public_key, 0, RSA_LEN);

    create_RSA_pair(rsa_private_key, rsa_public_key);

    printf("Public key is \n%s", rsa_public_key);

    //wait:    //Accept and incoming connection
    while(1){
        puts("Waiting for incoming connections...");
        addr_len = sizeof(struct sockaddr_in);

        //Accept connection from an incoming client
        client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&addr_len);
        if (client_sock < 0)
        {
            perror("accept failed");
            return 1;
        }
        puts("Connection accepted");

        //Send public key to client
        memset(client_message, 0, BUFFER_LEN);
        if(send(client_sock, rsa_public_key, BUFFER_LEN, 0) < 0)
        {
            puts("Send failed");
        }
        printf("Public key is sent to client\n");

        int encrypted_len = RSA_size_from(rsa_public_key,1);
        unsigned char * session_key_enc = (unsigned char *) malloc(encrypted_len * sizeof(char));
        memset(session_key_enc, 0, encrypted_len);

        unsigned char session_key[AES_KEY_LEN];
        memset(session_key, 0, AES_KEY_LEN);

        //Receive session key from client
        memset(client_message, 0, BUFFER_LEN);
        if ((recv(client_sock, client_message, BUFFER_LEN, 0)) <= 0) {
            puts("Recv failed!");
            exit -1;
        }

        memcpy(session_key_enc, client_message, encrypted_len);
        fflush(stdout);

        //Decrypt th random key
        int decrypted_length = private_decrypt(session_key_enc, encrypted_len, rsa_private_key, session_key);
	
        if (decrypted_length == -1)
        {
            printLastError("Public Decrypt failed ");
        }

        fflush(stdout);

        //Set the decryption key
        AES_KEY dec_key;
        AES_set_decrypt_key(session_key, AES_BITS, &dec_key);

        //Communication is established.
        //Receive data from client.
        memset(client_message, 0, BUFFER_LEN);
        while((read_size = recv(client_sock, client_message, BUFFER_LEN, 0)) > 0 )
        {
            fflush(stdout);
            printf("NEW MESSAGE\nReceived encrypted message is: <%s>\n\n", client_message);
            fflush(stdout);
            unsigned char dec_message[BUFFER_LEN];
            AES_decrypt(client_message, dec_message, &dec_key);

            fflush(stdout);
            printf("Decrypted message is \n%s\n\n", dec_message);
            fflush(stdout);

            char server_message[BUFFER_LEN] = "server received your request";
            send(client_sock, server_message, BUFFER_LEN , 0);
            memset(client_message, 0, BUFFER_LEN);

        }

        if(read_size == 0)
        {
            puts("Client disconnected");
            fflush(stdout);
        }
        else if(read_size == -1)
        {
            perror("recv failed");
        }

    }
}
