#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h> //install the required package
#include <sys/stat.h>
#include <limits.h>
#include <sys/file.h>

const char *LOG_FILE = "/tmp/access_audit.log";

char* file_path(FILE *stream){

    int fd = fileno(stream); //file descriptor from stream

    if (fd == -1) {
        return NULL;
    }

    char fd_path[PATH_MAX];             
    sprintf(fd_path, "/proc/self/fd/%d", fd);   //path of the fd

    char *path_buf = (char*)malloc(PATH_MAX);   
   
    if (path_buf == NULL) {
        return NULL;
    }

    ssize_t len = readlink(fd_path, path_buf, PATH_MAX - 1);  //find the real path(path_buf). len is the length of the path

    if (len == -1) {
        free(path_buf);
        return NULL;
    }
    else 
    {
        path_buf[len] = '\0'; //\0 in the end to end the string 
        return path_buf;
    }

}

char* file_hash(const char *filepath){

    
    static FILE*(*original_fopen)(const char*, const char*);

    if (!original_fopen) {
        original_fopen = dlsym(RTLD_NEXT, "fopen");
    }

    static int(*original_fclose)(FILE*);

    if (!original_fclose) {
        original_fclose = dlsym(RTLD_NEXT, "fclose");
    }

    FILE *file = original_fopen(filepath, "rb");
    
    if (file == NULL) {
        return NULL;
    }

    //tools for hash computation
    EVP_MD_CTX *mdctx;                              //place for the context
    const EVP_MD *md;                               //message digest algorithm (sha256)             
    unsigned char hash[EVP_MAX_MD_SIZE];            //buffer for the resulting hash (binary)
    unsigned int md_len;                            //length of the hash

    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();

    //begin hash computation
    EVP_DigestInit_ex(mdctx, md, NULL);

    unsigned char buffer[4096];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes_read);
    }

    //end hash computation  
    EVP_DigestFinal_ex(mdctx, hash, &md_len);
    EVP_MD_CTX_free(mdctx);
    original_fclose(file);

    //binary -> string
    char *hash_str = (char*)malloc(65); //32 bytes * 2 chars + 1('\0')

    if (hash_str == NULL) {
        return NULL;
    }

    for (int i =0; i < md_len; i++) {
        sprintf(&hash_str[i*2], "%02x", hash[i]);
    }
    hash_str[64] = '\0';

    return hash_str;
}

FILE *fopen(const char *path, const char *mode) 
{
    //the filename shoud be the absolute path

    char filename[PATH_MAX];

    if (realpath(path, filename) == NULL) {
        // try to build absolute path manually
        char cwd[PATH_MAX];                                                     // current working directory

        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            snprintf(filename, sizeof(filename), "%s/%s", cwd, path);
        } 
    }


    // check if filename is the log file
    if (strcmp(filename, LOG_FILE) == 0) {
        FILE *(*original_fopen)(const char*, const char*) =  dlsym(RTLD_NEXT, "fopen");
        return original_fopen(path, mode);
    }

    struct stat fstat;
    int file_exists = (stat(filename, &fstat) == 0);  //check if file exists -1 (not exist)


    FILE *original_fopen_ret;
    FILE *(*original_fopen)(const char*, const char*);

    // call the original fopen function
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    original_fopen_ret = (*original_fopen)(path, mode);  //here we create or open the file


    /* add your code here */

    //log field values
    uid_t uid = getuid();
    pid_t pid = getpid();

    char date_str[11]; // YYYY-MM-DD + \0
    char time_str[9];  // HH:MM:SS + \0

    time_t now = time(NULL);
    struct tm *utc = gmtime(&now);

    strftime(date_str, sizeof(date_str), "%Y-%m-%d", utc);
    strftime(time_str, sizeof(time_str), "%H:%M:%S", utc);

    int operation;
    int denied_flag;

    if (original_fopen_ret == NULL) {
        denied_flag = 1;
        operation = 1; // open
    }
    else if (file_exists) {
        denied_flag = 0;
        operation = 1; // open existing
    }
    else {
        denied_flag = 0;
        operation = 0; // create new
    }

    char *filehash = file_hash(filename);

    //open log file using original_fopen to avoid recursion 
    FILE *log_file = original_fopen(LOG_FILE, "a"); 

    if (log_file) {
        int log_fd = fileno(log_file);

        //lock the log file for use
        flock(log_fd, LOCK_EX);

        fprintf(log_file, "%d,%d,%s,%s,%s,%d,%d,%s\n",
                uid,
                pid,
                filename,
                date_str,
                time_str,
                operation,
                denied_flag,
                filehash ? filehash : "NULL"
        );

        //unlock the log file for the next process
        flock(log_fd, LOCK_UN);
        fclose(log_file);
    }

    free(filehash);

    return original_fopen_ret;
}



size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{

    size_t original_fwrite_ret;
    size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

    /* call the original fwrite function */
    original_fwrite = dlsym(RTLD_NEXT, "fwrite");
    original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

    /* add your code here */
    uid_t uid = getuid();
    pid_t pid = getpid();

    /* get the filename (malloc'd by file_path) */
    char *filename = file_path(stream);

    if (filename == NULL) {
        return original_fwrite_ret;
    }

    // check if filename is the log file
    if (strcmp(filename, LOG_FILE) == 0) {
        free(filename);
        return original_fwrite_ret;
    }

    char date_str[11]; // YYYY-MM-DD + \0
    char time_str[9];  // HH:MM:SS + \0

    time_t now = time(NULL);
    struct tm *utc = gmtime(&now);

    strftime(date_str, sizeof(date_str), "%Y-%m-%d", utc);
    strftime(time_str, sizeof(time_str), "%H:%M:%S", utc);

    int operation = 2; // write

    if (nmemb == 0){
        return original_fwrite_ret;
    }

    int denied_flag;
    if (original_fwrite_ret == 0 && nmemb > 0) {
        denied_flag = 1;
    } else {
        denied_flag = 0;
    }

    char *filehash = file_hash(filename);

    //open log using original fopen to avoid recursion
    FILE *(*original_fopen)(const char*, const char*);
    original_fopen = dlsym(RTLD_NEXT, "fopen");

    FILE *log_file = original_fopen(LOG_FILE, "a");
    if (log_file) {
        int log_fd = fileno(log_file);
        flock(log_fd, LOCK_EX);
        fprintf(log_file, "%d,%d,%s,%s,%s,%d,%d,%s\n",
                uid,
                pid,
                filename,
                date_str,
                time_str,
                operation,
                denied_flag,
                filehash ? filehash : "NULL"
        );
        flock(log_fd, LOCK_UN);
        fclose(log_file); //close the log 
    }

    free(filename);
    free(filehash);

    return original_fwrite_ret;
}



int fclose(FILE *stream)
{
    char *filename = file_path(stream);// we call it first to get the filename before closing the stream

    int original_fclose_ret;
    int (*original_fclose)(FILE*);

    /* call the original fclose function */
    original_fclose = dlsym(RTLD_NEXT, "fclose");

    /* add your code here */

    //close if filename does not exist
    if (filename == NULL) {
        return original_fclose(stream);
    }

    original_fclose_ret = (*original_fclose)(stream);

    //check if filename is the log file
    if (strcmp(filename, LOG_FILE) == 0) {
        free(filename);
        return original_fclose_ret;
    }

    /* log fields */
    uid_t uid = getuid();
    pid_t pid = getpid();

    char date_str[11]; // YYYY-MM-DD + \0
    char time_str[9];  // HH:MM:SS + \0

    time_t now = time(NULL);
    struct tm *utc = gmtime(&now);

    strftime(date_str, sizeof(date_str), "%Y-%m-%d", utc);
    strftime(time_str, sizeof(time_str), "%H:%M:%S", utc);

    int operation = 3; // close

    int denied_flag;

    if (original_fclose_ret == 0){
        denied_flag = 0;
    }
    else
    {
        denied_flag = 1;
    }

    char *filehash = file_hash(filename);

    FILE *(*original_fopen)(const char*, const char*);
    original_fopen = dlsym(RTLD_NEXT, "fopen");

    FILE *log_file = original_fopen(LOG_FILE, "a");
    if (log_file) {
        int log_fd = fileno(log_file);
        flock(log_fd, LOCK_EX);
        fprintf(log_file, "%d,%d,%s,%s,%s,%d,%d,%s\n",
                uid, 
                pid, 
                filename,
                date_str, 
                time_str,
                operation, 
                denied_flag,
                filehash ? filehash : "NULL");
        flock(log_fd, LOCK_UN);
        fclose(log_file);
    }

    free(filename);
    free(filehash);

    return original_fclose_ret;
}