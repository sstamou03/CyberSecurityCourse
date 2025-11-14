#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

struct log_entry {

	int uid; /* user id (positive integer) */
	pid_t pid; /* process id (positive integer) */

	char *file; /* filename (string) */

	char *date; /* file access date - utc*/
	char *time; /* file access time - utc*/

	int operation; /* access type values [0-3] */
	int action_denied; /* is action denied values [0-1] */

	char *filehash; /* file hash - sha256 - evp */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

};

struct DenFile {
    /* linked list of denied files */
    char *filename;
    struct DenFile *next;
};

struct BadUser {
/* linked list of bad users */
    int uid;
    int disitnct_files;
    struct DenFile *head;
    struct BadUser *next;
};

struct modification {
    /* linked list of modifications per user */
    int uid;
    int modifications_count;
    struct modification *next;
};

struct UniqueModification{
    char *hash;
    struct UniqueModification *next;
};

struct log_entry* parser(char *line){

    /*take the values of the logfile and parse them into the values of the above struct*/

    struct log_entry *entry = malloc(sizeof(struct log_entry));

    if (entry == NULL) {
        return NULL;
    }

    char *token; 
    char *saveptr; 

    //uid to int
    token = strtok_r(line, ",", &saveptr);
    if (token == NULL){

        free(entry);
        return NULL;
    }
    entry->uid = atoi(token); 

    //pid to int
    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL){

        free(entry);
        return NULL;
    }
    entry->pid = (pid_t)atoi(token);

    //file to string
    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL){

        free(entry);
        return NULL;
    }
    entry->file = strdup(token);

    //date to string
    token = strtok_r(NULL, ",", &saveptr);
    if(token == NULL){

        free(entry);
        return NULL;
    }
    entry->date = strdup(token);

    //time to string
    token = strtok_r(NULL, ",", &saveptr);
    if(token == NULL){

        free(entry);
        return NULL;
    }
    entry->time = strdup(token);

    //operation to int
    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL){

        free(entry);
        return NULL;
    }
    entry->operation = atoi(token);

    //action_denied to int
    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL){

        free(entry);
        return NULL;
    }
    entry->action_denied = atoi(token);

    //filehash to string
    token = strtok_r(NULL, "\n", &saveptr);
    if (token == NULL){

        free(entry);
        return NULL;
    }
    entry->filehash = strdup(token);

    return entry;
}


void usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./audit_monitor \n"
		   "Options:\n"
		   "-s, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}




void list_unauthorized_accesses(FILE *log){
    char line[2048];
    struct BadUser *head = NULL; // init the head of the list
    struct log_entry *entry;

    //rtfl
    while (fgets(line, sizeof(line), log) != NULL){

        entry = parser(line);

        if (entry == NULL){
            continue;
        }

        if (entry->action_denied == 1){
            /* only the denied */
            struct BadUser *current_user = head;
            // lets find if we have seen this user in our list
            while (current_user != NULL){
                if (current_user->uid == entry->uid){
                    
                    break; //got him. BLYAT

                }
                current_user = current_user->next;
            }

            if (current_user == NULL){
                // BLYAT. add new bad user
                current_user = malloc(sizeof(struct BadUser));
                current_user->uid = entry->uid;
                current_user->disitnct_files = 0;
                current_user->head = NULL;  
                current_user->next = head;  //put him at the start
                head = current_user;
            }

            //now lets find if we have seen this file for this user
            struct DenFile *current_file = current_user->head;
            while (current_file != NULL){
                if (strcmp(current_file->filename, entry->file) == 0){
                    
                    break; //got the file
                
                }
                current_file = current_file->next;
            }

            if (current_file == NULL){
                // BLYAT. add new denied file
                current_file = malloc(sizeof(struct DenFile));
                current_file->filename = strdup(entry->file);
                current_file->next = current_user->head; //put it at the start
                current_user->head = current_file;
                current_user->disitnct_files ++;
            }


        }

            free(entry->file);
            free(entry->date);
            free(entry->time);
            free(entry->filehash);
            free(entry);
        
    }               
    
    printf("=======================================\n");
    printf("Analysis for suspicious users.BLYAT!\n");
    printf("=======================================\n");
    printf("Suspicious Users -> (got denied more than 5 times)\n");
    struct BadUser *counter = head;
    int found = 0;

    while (counter != NULL){
        if (counter->disitnct_files > 5){
            found = 1;
            printf("BLYAT GOT HIM! User with UID %d have %d distinct denied files\n", counter->uid, counter->disitnct_files);
        }
        counter = counter->next;
    }

    if (found == 0){

        printf("Well no suspicious users found.\n");


    }

    //free user list and files lists
    struct BadUser *temp_user;
    struct DenFile *temp_file;
    counter = head;
    while (counter != NULL){
        temp_user = counter;
        counter = counter->next;

        struct DenFile *file_counter = temp_user->head;
        while (file_counter != NULL){
            temp_file = file_counter;
            file_counter = file_counter->next;
            free(temp_file->filename);
            free(temp_file);
        }

        free(temp_user);
    }

    //fclose(log);
	return;
}


void list_file_modifications(FILE *log, char *file_to_scan)
{

    char abs_path_to_scan[PATH_MAX];

    if (realpath(file_to_scan, abs_path_to_scan) == NULL) {

        // The logger ALWAYS logs absolute paths, so we must also construct one.
        if (file_to_scan[0] == '/') {
            // already absolute path
            strncpy(abs_path_to_scan, file_to_scan, PATH_MAX - 1);
            abs_path_to_scan[PATH_MAX - 1] = '\0';
        } else {
            // Make absolute path based on current working directory
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd)) != NULL) {
                snprintf(abs_path_to_scan, PATH_MAX, "%s/%s", cwd, file_to_scan);
            } else {
                // fallback
                strncpy(abs_path_to_scan, file_to_scan, PATH_MAX - 1);
                abs_path_to_scan[PATH_MAX - 1] = '\0';
            }
        }
    }


    char line[2048];
    struct modification *head = NULL; // init the head of the list
    struct UniqueModification *hash_head = NULL;
    struct log_entry *entry;
    int total_modifications = 0;

    //rtfl
    while (fgets(line, sizeof(line), log) != NULL){

        entry = parser(line);

        if (entry == NULL){
            continue;
        }

        if (strcmp(entry->file, abs_path_to_scan)==0){
            struct modification *current_user = head;
            // lets find if we have seen this user in our list
            while (current_user != NULL){
                if (current_user->uid == entry->uid){
                    
                    break; //got him. BLYAT

                }
                current_user = current_user->next;
            }

            if (current_user == NULL){
                // BLYAT. add new user
                current_user = malloc(sizeof(struct modification));
                current_user->uid = entry->uid;
                current_user->modifications_count = 0;
                current_user->next = head;  //put him at the start
                head = current_user;
            }

            if (entry->operation == 2){ //write operation
                current_user->modifications_count ++;
            }

            struct UniqueModification *current_hash = hash_head;
            while (current_hash != NULL){
                if (strcmp(current_hash->hash, entry->filehash) == 0){
                    
                    break; //got the hash
                
                }
                current_hash = current_hash->next;
            }

            if (current_hash == NULL){
                // BLYAT. add new unique hash
                current_hash = malloc(sizeof(struct UniqueModification));
                current_hash->hash = strdup(entry->filehash);
                current_hash->next = hash_head; //put it at the start
                hash_head = current_hash;
                total_modifications ++;
            }
        }

            free(entry->file);
            free(entry->date);
            free(entry->time);
            free(entry->filehash);
            free(entry);

    }
    printf("===============================\n");
    printf("Analysis for file activity.BLYAT!\n");
    printf("===============================\n");
    printf("File scanned: %s\n", abs_path_to_scan);

    struct modification *counter = head;

    if (counter == NULL){
        printf("No user accessed this file.\n");
    }

    while (counter != NULL){
        printf("BLYAT GOT HIM! User with UID %d modified the file %d times\n", counter->uid, counter->modifications_count);
        counter = counter->next;
    }
    printf("Unique modifications that occured %d\n", total_modifications); //real modifications

    //free user list and unique hash list
    struct modification *temp_user;
    struct UniqueModification *temp_hash;
    counter = head;
    while (counter != NULL){
        temp_user = counter;
        counter = counter->next;
        free(temp_user);
    }
    struct UniqueModification *hash_counter = hash_head;
    while (hash_counter != NULL){
        temp_hash = hash_counter;
        hash_counter = hash_counter->next;
        free(temp_hash->hash);
        free(temp_hash);
    }

	return;

}


int main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("/tmp/access_audit.log", "r");
    if (log == NULL) {
        printf("Error opening log file \"%s\"\n", "/tmp/access_audit.log");
        return 1;
    }

	while ((ch = getopt(argc, argv, "hi:s")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 's':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
