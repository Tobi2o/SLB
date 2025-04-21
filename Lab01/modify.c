#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>

int writeIntoFile(FILE* fp, int data){
    fseek(fp,-1L,SEEK_CUR);
    return fputc(data, fp);
}

void encrypt(FILE* fp){
     int ch;
     
     const unsigned CONST_XOR = 0xff;

    while ((ch = fgetc(fp)) != EOF){
        
        int temp = ch ^ CONST_XOR;
        
        if(writeIntoFile(fp,temp) == EOF){
            fprintf(stderr, "Failed to write into file  \n");
            return -1;
        }
    }
}

int main(int argc, char** argv){

    FILE *fp;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file to encrypt>\n", argv[0]);
        return -1;
    }

    /* Opening the file */
    fp = fopen(argv[1], "r+");

    if (fp == NULL) {
        fprintf(stderr, "Failed to open file %s\n", argv[1]);
        return -1;
    }

    encrypt(fp);

    /* Close the file */
    fclose(fp);
    return 0;
}
