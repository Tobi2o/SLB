#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <memory.h>
#include <dirent.h>

#include "main.h"

void decrypt0(FILE* inputFile) {
    int readCharFromFile;
    char res;

    while (1) {
        readCharFromFile = fgetc(inputFile);
        fseek(inputFile,-1,SEEK_CUR);
        if (readCharFromFile == EOF) {
            printf("End of file\n");
            break;
        }

        res = (char)readCharFromFile ^ 0xef;
        if ((res & 2) == 0) {
            fputc(res, inputFile);
            continue;
        }

        res = (char)readCharFromFile ^ 0xbe;
        fputc(res, inputFile);
    }

    printf("Decryption completed\n");
}

void decrypt1(FILE *fp) {
    int byteFromFile;
    int var = 7;
    char res;

    while(1) {
        byteFromFile = fgetc(fp);
        fseek(fp, -1, SEEK_CUR);

        if (byteFromFile == EOF) break;

        res = (((byteFromFile-var)&0xFF) << 6) | (((byteFromFile-var)&0xFF) >> 2);

        var = byteFromFile >> 2 | byteFromFile * '@';
        fputc(res,fp);

    }
}

void decrypt2(FILE *file){

    byte local_40 [16] = {1, 211, 7, 21, 107, 10, 0, 0, 0, 187, 211, 7, 21, 107, 10, 0};
    uint local_18;
    byte local_11;

    fseek(file, -1, 2);
    int nb_bytes = ftell(file);
    local_11 = (byte)fgetc(file);
    local_11 -= nb_bytes * 4;
    fseek(file, 0, 0);
    uint filesize = 0;

    while(1){
        int byte_from_file = fgetc(file);
        if(byte_from_file == -1)break;
        fseek(file,-1,SEEK_CUR);
        byte_from_file = (int)(char)((byte)byte_from_file ^ local_11);
        local_11 += 4;
        fputc(byte_from_file, file);
    }

    local_18 = 0;

    fseek(file, 0, 0);

    int i = 0;
    while(i < filesize-1){
        int byte_from_file = fgetc(file);
        if (byte_from_file == -1) break;
        fseek(file,-1,1);
        local_18 = local_18 + 5 & 0xe;
        byte_from_file = (int)(char)(byte)byte_from_file + (int)(char)local_40[local_18 + 1];
        fputc(byte_from_file,file);
    }
    return;
}

void decrypt_dir(char *buffer_current_directory_path , char *buffer_symbolic_proc_self_exe){
    int cmp;
    char file_path [4096];
    uint occurences;
    size_t length;
    FILE *file_stream;
    struct dirent *dir_stream;
    DIR *dir;

    dir = opendir(buffer_current_directory_path);
    if (dir != (DIR *)0x0) {
        while (dir_stream = readdir(dir), dir_stream != (struct dirent *)0x0) {
            snprintf(file_path,0x1000,"%s/%s",buffer_current_directory_path,dir_stream->d_name);
            if (dir_stream->d_type == '\x04') {
                cmp = strcmp(dir_stream->d_name,".");
                if ((cmp != 0) && (cmp = strcmp(dir_stream->d_name,".."), cmp != 0)) {
                    decrypt_dir(file_path,buffer_symbolic_proc_self_exe);
                }
            }
            else if ((dir_stream->d_type == '\b') && (cmp = strcmp(file_path,buffer_symbolic_proc_self_exe), cmp != 0)
                    ) {
                file_stream = fopen(file_path,"r+");
                length = strlen(dir_stream->d_name);
                occurences = char_occurences(dir_stream->d_name,length,0x73);
                occurences = occurences & 3;
                if (occurences == 0) {
                 decrypt0(file_stream);
                }
                else if (occurences == 1) {
                  decrypt1(file_stream);
                }
                else {
                  decrypt2(file_stream);
                }
                fclose(file_stream);
            }
        }
        closedir(dir);
    }
}

int char_occurences(char * string,uint count,char letter)
{

    uint counter = 0;
    for (int i = 0; i < count; ++i) {
        if (letter == *(char *)(i + string)) {
            counter = counter + 1;
        }
    }
    return counter;
}


int main(void) {
    int RL = 0;
    char *cwd = 0;
    char buffer_current_directory_path [4096];
    char buffer_symbolic_proc_self_exe [4096];
    memset(buffer_symbolic_proc_self_exe,0,0x1000);
    cwd = getcwd(buffer_current_directory_path,0x1000);
    if (cwd == (char *)0x0) {
        return -1;
    }
    RL = readlink("/proc/self/exe",buffer_symbolic_proc_self_exe,0x1000);
    if (RL != -1) {
        decrypt_dir(buffer_current_directory_path,buffer_symbolic_proc_self_exe);
    }

    return 0;
}