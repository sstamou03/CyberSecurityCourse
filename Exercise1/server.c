#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#define FAIL -1

int OpenListener(int port) {
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Can't bind port");
        abort();
    }

    if (listen(sd, 10) != 0) {
        perror("Can't configure listening port");
        abort();
    }

    return sd;
}

SSL_CTX* InitServerCTX(void) {
    /* TODO:
     * 1. Initialize SSL library (SSL_library_init, OpenSSL_add_all_algorithms, SSL_load_error_strings)
     * 2. Create a new TLS server context (TLS_server_method)
     * 3. Load CA certificate for client verification
     * 4. Configure SSL_CTX to require client certificate (mutual TLS)
     */
    SSL_CTX *ctx = NULL;
    SSL_METHOD *meth = NULL; 

    //1
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    //2
    meth = TLSv1_2_server_method();
    ctx = SSL_CTX_new(meth);

    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    

    //3
    if(SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) == 0){
        ERR_print_errors_fp(stderr);
        abort();
    }

    //4
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {
    /* TODO:
     * 1. Load server certificate using SSL_CTX_use_certificate_file
     * 2. Load server private key using SSL_CTX_use_PrivateKey_file
     * 3. Check that private key matches the certificate using SSL_CTX_check_private_key
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

void ShowCerts(SSL* ssl) {
    /* TODO:
     * 1. Get client certificate (if any) using SSL_get_peer_certificate
     * 2. Print Subject and Issuer names
     */
    
    X509 *cert;
    char *line;

    //1
    cert = SSL_get_peer_certificate(ssl);

    //2
    if (cert != NULL) {

        printf("Client certificates:\n");

        
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line); 

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line); 

        X509_free(cert); 

    } else {
        printf("No client certificate provided.\n");
    }

}

void Servlet(SSL* ssl) {
    char buf[1024] = {0};

    if (SSL_accept(ssl) == FAIL) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr,
            "Server response: peer did not return a certificate or returned an invalid one\n");
        return;
    }

    ShowCerts(ssl);

    int bytes = SSL_read(ssl, buf, sizeof(buf));
    if (bytes <= 0) {
        SSL_free(ssl);
        return;
    }
    buf[bytes] = '\0';
    printf("Client message: %s\n", buf);

    /* TODO:
     * 1. Parse XML from client message to extract username and password
     * 2. Compare credentials to predefined values (e.g., "sousi"/"123")
     * 3. Send appropriate XML response back to client
     */

    //1 
    char username[100] = {0};
    char password[100] = {0};

    char *usernamest = strstr(buf, "<UserName>");
    char *passwordst = strstr(buf, "<Password>");

    if(usernamest && passwordst){
        sscanf(usernamest + strlen("<UserName>"), "%99[^<]", username);
        sscanf(passwordst + strlen("<Password>"), "%99[^<]", password);
    }

    //2,3
    char *name = "Giannakopoulos";
    char *pass = "131313";

    const char *response = "<Body>\n<Name>olaprasina.com</Name>\n<year>1.5</year>\n<BlogType>Embedede and c c++</BlogType>\n<Author>kendrick nunn</Author>\n</Body>";

    if (strcmp(username, name) == 0 && strcmp(password, pass) == 0)
    {
        SSL_write(ssl, response, strlen(response));
    }
    else {
        SSL_write(ssl, "No Blyat.Invalid Message", strlen("No Blyat.Invalid Message"));
    }
    

    int sd = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sd);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(0);
    }

    int port = atoi(argv[1]);
    SSL_CTX *ctx;

    /* TODO:
     * 1. Initialize SSL context using InitServerCTX
     * 2. Load server certificate and key using LoadCertificates
     */
    
     //1
     ctx = InitServerCTX();
     //2
     LoadCertificates(ctx, "server.crt", "server.key");


    int server = OpenListener(port);

    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr*)&addr, &len);
        printf("\nConnection from %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        /* TODO:
         * 1. Create new SSL object from ctx
         * 2. Set file descriptor for SSL using SSL_set_fd
         * 3. Call Servlet to handle the client
         */

        //1
        ssl = SSL_new(ctx);
        //2
        SSL_set_fd(ssl, client);
        //3
        Servlet(ssl);
    }

    close(server);
    SSL_CTX_free(ctx);
}
