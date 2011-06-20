#include <iostream>
#include <cstring>

//Sockets
#include <arpa/inet.h>
#include <sys/socket.h>

//OpenSSL headers
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#define PORT "3"

using namespace std;

int create_socket_and_listen(int port) {
    int s;
    struct sockaddr_in sin;

    s = socket(AF_INET,SOCK_STREAM,0);
    memset(&sin,0,sizeof(sin));
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_family      = AF_INET;
    sin.sin_port        = htons( port );

    int ret = bind( s, (struct sockaddr*) &sin, sizeof(sin) );
    if ( ret < 0 ) {
        perror("Can't bind port");
        exit(EXIT_FAILURE);
    }

    if( listen( s, 0 )<0 ) {
        perror("Can't listen");
        exit(EXIT_FAILURE);
    }

    return(s);
}

void openssl_init() {
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();

}

int main() {

    BIO *bio;
    SSL_CTX *ctx;
    SSL *ssl;

    //Initialize OpenSSL
    openssl_init();

    //Set up ctx
    ctx = SSL_CTX_new( TLSv1_server_method() ); //Set the connection method
    SSL_CTX_use_certificate_file(ctx, "/home/vicent/server.pem", SSL_FILETYPE_PEM); //Load certificate from a PEM file
    SSL_CTX_use_PrivateKey_file(ctx, "/home/vicent/server.pem", SSL_FILETYPE_PEM); //Load private key

    //Create acceptor socket (TCP) and listen on it
    int asock = create_socket_and_listen(4433);

    //Accepts connections on asock, creates a new connected socket (osock), and returns a new file descriptor referring to that socket
    struct sockaddr_in sa_cli;
    int client_len;
    int osock = accept(asock, (struct sockaddr*)&sa_cli, (socklen_t*)&client_len);

    //Create bio and ssl objects
    bio = BIO_new_socket(osock, BIO_NOCLOSE); //Returns a socket BIO using osock
    ssl = SSL_new(ctx);
    SSL_set_bio(ssl, bio, bio);

    int ret = SSL_accept(ssl); //Wait for a handshake
    if( ret <=0 ) {
        /* Handle fail here */
        cerr<< "Error:" << ERR_reason_error_string( SSL_get_error(ssl,ret) ) << endl;
    }

    char buf[50];
    ret = SSL_read(ssl, buf, sizeof(buf)-1);

    //Create a new SSL BIO
    /*bio = BIO_new_ssl(ctx, 0); // 0 -> Server | 1 -> Client
    if(bio == NULL) {
        //Handle failure here
        cerr<< "Error:" << ERR_reason_error_string( ERR_get_error() ) << endl;
    }*/

    //Change settings in the SSL pointer of bio
    /*BIO_get_ssl(bio, &ssl); //Retrieves the SSL pointer of BIO bio, it can then be manipulated using the standard SSL library functions.
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    //Set up the accept BIO
    abio = BIO_new_accept( (char*)"1420" );
    BIO_set_accept_bios(abio, bio);


    //Set up abio for accepting incoming connections
    if(BIO_do_accept(abio) <= 0) {
        // Handle fail here
        cerr<< "Error:" << ERR_reason_error_string( ERR_get_error() ) << endl;
    }

    //Second call to actually wait
    if(BIO_do_accept(abio) <= 0) {
        // Handle fail here
        cerr<< "Error:" << ERR_reason_error_string( ERR_get_error() ) << endl;
    }

    //Pop out another bio for talking with the client and do the handshake
    obio = BIO_pop(abio);
    if(BIO_do_handshake(obio) <= 0) {
        // Handle fail here
        cerr<< "Error:" << ERR_reason_error_string( ERR_get_error() ) << endl;
    }
    */
    //Read

    int x = BIO_read(bio, buf, 50);
    if(x == 0) {
        /* Handle closed connection */
    } else if(x < 0) {
        if(! BIO_should_retry(bio)) {
            /* Handle failed read here */
        }

        /* Do something to handle the retry */
    }

    cout<<buf;
    return 0;
}

