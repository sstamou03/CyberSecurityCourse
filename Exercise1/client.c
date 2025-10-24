#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL)
    {
        perror(hostname);
        abort();
    }

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        close(sd);
        perror("Connection failed");
        abort();
    }

    return sd;
}

SSL_CTX* InitCTX(void)
{
    /* TODO:
     * 1. Initialize SSL library (SSL_library_init, OpenSSL_add_all_algorithms, SSL_load_error_strings)
     * 2. Create a new TLS client context (TLS_client_method)
     * 3. Load CA certificate to verify server
     * 4. Configure SSL_CTX to verify server certificate
     */
    SSL_CTX *ctx = NULL;
    SSL_METHOD *meth = NULL; 

    
    //1
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    //2
    meth = TLSv1_2_client_method();
    ctx = SSL_CTX_new(meth);

    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    //3
        //3
    if(SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) == 0){
        ERR_print_errors_fp(stderr);
        abort();
    }

    //4
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* TODO:
     * 1. Load client certificate using SSL_CTX_use_certificate_file
     * 2. Load client private key using SSL_CTX_use_PrivateKey_file
     * 3. Verify that private key matches certificate using SSL_CTX_check_private_key
     */

     //1
     if(SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM)!= 1){
        ERR_print_errors_fp(stderr);
        abort();
     }
     //2
     if(SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM)!= 1){
        ERR_print_errors_fp(stderr);
        abort();
     }
     //3
     if (!SSL_CTX_check_private_key(ctx))
     {
        fprintf(stderr, "Private key does not match the public certificate.\n");
        abort();
     }
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <hostname> <port>\n", argv[0]);
        exit(0);
    }

    char *hostname = argv[1];
    int port = atoi(argv[2]);
    SSL_CTX *ctx;
    SSL *ssl;
    int server;

    /* TODO:
     * 1. Initialize SSL context using InitCTX
     * 2. Load client certificate and key using LoadCertificates
     */
    //1
    ctx = InitCTX();
    //2
    LoadCertificates(ctx, "client.crt", "client.key");

    server = OpenConnection(hostname, port);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);

    /* TODO:
     * 1. Establish SSL connection using SSL_connect
     * 2. Ask user to enter username and password
     * 3. Build XML message dynamically
     * 4. Send XML message over SSL
     * char username[64], password[64];
        printf("Enter username: ");
        scanf("%63s", username);
        printf("Enter password: ");
        scanf("%63s", password);

        char msg[256];
        snprintf(msg, sizeof(msg),
                 "<Body><UserName>%s</UserName><Password>%s</Password></Body>",
                 username, password);

        SSL_write(ssl, msg, strlen(msg));
     * 5. Read server response and print it
     */
    
     //1
     if (SSL_connect(ssl) == FAIL)
     {
        ERR_print_errors_fp(stderr);
     }
     //2
     else {
        printf("Successfully connected.Blyat!\n");

        char username[100];
        char password[100];

        printf("\nEnter your username:");
        scanf("%99s", username);

        printf("\nEnter your password:");
        scanf("%99s", password);

        //3
        char msg[256];
        snprintf(msg, sizeof(msg),"<Body><UserName>%s</UserName><Password>%s</Password></Body>",username, password);
        
        //4
        SSL_write(ssl, msg, strlen(msg));

        //5
        char buf[1024] = {0};
        int bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
        
        if (bytes > 0) {
            buf[bytes] = '\0';
            printf("Response:\n%s\n", buf); 
        } else {
            ERR_print_errors_fp(stderr);
        }
    }
     
    SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}
