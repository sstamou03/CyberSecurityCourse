#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void writef(const char *filename, const char *data, const char *mode) {
    FILE *file = fopen(filename, mode);
    if (file != NULL) {
        fwrite(data, strlen(data), 1, file);
        fclose(file);
    }
}

int main() 
{

    printf("Test for the Audit System \n");
    printf("1)Creating and modifying 10 files\n");


	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};



	/* example source code */

	for (i = 0; i < 10; i++) {

		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
	}

    printf("2)Opening existing files\n");

    for (i = 0; i < 10; i++) {

        file = fopen(filenames[i], "r");

        if (file == NULL){

            printf("fopen error\n");
        }
        else {
            fclose(file);
        }

    }

    printf("3)Create 6 unique versions of file_11\n");

    writef("file_11", "Initial content", "w");
    writef("file_11", "2 version", "w");
    writef("file_11", "2 version", "w");
    writef("file_11", "2 version", "w");
    writef("file_11", "2.1 version", "a");
    writef("file_11", "3 version", "w");
    writef("file_11", "3 version", "w");
    writef("file_11", "3 version", "w");
    writef("file_11", "3.1 version", "a");
    writef("file_11", "Final version", "w");


    printf("4)Test for suspicious activity\n");
    char restricted_files[8][15] = {"restrict_0", "restrict_1", "restrict_2", "restrict_3",
                                    "restrict_4", "restrict_5", "restrict_6", "restrict_7"};

    
    for (i = 0; i < 8; i++) {

        writef(restricted_files[i], "Restricted content", "w");
        chmod(restricted_files[i], 0000); //no permissions
    }

    printf("5)Trying to access restricted files\n");

    for (i = 0; i < 8; i++) {

        file = fopen(restricted_files[i], "r");
        file = fopen(restricted_files[i], "w");
        file = fopen(restricted_files[i], "a");
    }

    printf("6)Read on a non existing file\n");
    file = fopen("non_existing_file.txt", "r");

    if (file == NULL){

        printf("fopen error\n");
    }
    else {
        fclose(file);
    }

    for (i = 0; i < 10; i++) {
        remove(filenames[i]);
    }
    
    remove("file_11");
    
    for (i = 0; i < 8; i++) {
        chmod(restricted_files[i], 0644); 
        remove(restricted_files[i]);     
    }

    printf("BLYAT!Test completed\n");
    
    return 0;


}