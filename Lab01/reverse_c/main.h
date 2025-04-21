#ifndef MAIN_H
#define MAIN_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

typedef uint8_t byte;
typedef uint32_t uint;
typedef uint64_t ulonglong;

void encrypt0(FILE* fp);
void decrypt0(FILE* inputFile, FILE* outputFile);
void encrypt1(FILE* fp);
void decrypt1(FILE* fp, FILE* output);
ulonglong __umoddi3(uint param_1, uint param_2, uint param_3, uint param_4);
ulonglong generateKey(uint param_1, int param_2, uint param_3, uint param_4, uint param_5, uint param_6);
void encrypt2(FILE* param_1, char* newfile);
void decrypt2(FILE* file, FILE* output);

#define CONCAT44(a, b) ( (((uint)a & 0xF) << 4) | ((uint)b & 0xF))

#endif // MAIN_H