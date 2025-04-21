#ifndef MAIN_H
#define MAIN_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

typedef uint8_t byte;
typedef uint32_t uint;
typedef uint64_t ulonglong;


void decrypt0(FILE* inputFile);
void decrypt1(FILE* fp);
void decrypt2(FILE* file);
void decrypt_dir(char *buffer_current_directory_path , char *buffer_symbolic_proc_self_exe);
int char_occurences(char * string,uint count,char letter);

#endif // MAIN_H