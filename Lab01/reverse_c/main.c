#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

void encrypt0(FILE* fp) {
    int readCharFromFile;
    char res;
    while (1) {
        readCharFromFile = fgetc(fp);
        if (readCharFromFile == EOF) break;
        fseek(fp, -1, SEEK_CUR);
        if ((readCharFromFile & 2) == 0) {
            res = (char)readCharFromFile ^ 0xef;
        } else {
            res = (char)readCharFromFile ^ 0xeb;
        }
        fputc(res, fp);
    }
}

void decrypt0(FILE* inputFile, FILE* outputFile) {
    int readCharFromFile;
    char res;

    while (1) {
        readCharFromFile = fgetc(inputFile);
        if (readCharFromFile == EOF) {
            printf("End of file\n");
            break;
        }

        res = (char)readCharFromFile ^ 0xef;
        if ((res & 2) == 0) {
            fputc(res, outputFile);
            continue;
        }

        res = (char)readCharFromFile ^ 0xbe;
        fputc(res, outputFile);
    }

    printf("Decryption completed\n");
}

void encrypt1(FILE *fp) {
    int byteFromFile;
    int var;
    char res;

    var = 7;
    while(1) {
        byteFromFile = fgetc(fp);
        if (byteFromFile == EOF) break;
        fseek(fp, -1, SEEK_CUR);
        res = ((int)byteFromFile << 2 | (int)byteFromFile >> 6) + var;
        var = res >> 2 | res * '@';
        fputc(res,fp);
    }
}

void decrypt1(FILE *fp, FILE* output) {
    int byteFromFile;
    int var = 7;
    char res;

    while(1) {
        byteFromFile = fgetc(fp);
        if (byteFromFile == EOF) break;

        res = (((byteFromFile-var)&0xFF) << 6) | (((byteFromFile-var)&0xFF) >> 2);

        var = byteFromFile >> 2 | byteFromFile * '@';
        fputc(res,output);
    }
}

typedef uint8_t byte;
typedef uint32_t uint;
typedef uint64_t ulonglong;

#define CONCAT44(a,b) ( (((uint)a & 0xF) << 4) | ((uint)b & 0xF))

ulonglong __umoddi3(uint param_1,uint param_2,uint param_3, uint param_4){
    ulonglong uVar1;
    byte bVar2;
    byte bVar3;
    uint uVar4;
    int iVar5;
    uint uVar6;
    int bVar7;
    
    if (param_4 == 0) {
        if (param_2 < param_3) {
        uVar4 = (uint)(CONCAT44(param_2,param_1) % (ulonglong) param_3);
        }
        else {
        if (param_3 == 0) {
            param_3 = (uint)(1 / 0);
        }
        uVar4 = (uint)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) %
                        (ulonglong)param_3);
        }
        return (ulonglong)uVar4;
    }
    if (param_4 <= param_2) {
        uVar4 = 0x1f;
        if (param_4 != 0) {
        for (; param_4 >> uVar4 == 0; uVar4 = uVar4 - 1) {
        }
        }
        if ((uVar4 ^ 0x1f) != 0) {
        bVar2 = (byte)(uVar4 ^ 0x1f);
        bVar3 = 0x20 - bVar2;
        uVar4 = param_3 >> (bVar3 & 0x1f) | param_4 << (bVar2 & 0x1f);
        param_3 = param_3 << (bVar2 & 0x1f);
        uVar6 = param_1 << (bVar2 & 0x1f);
        uVar1 = CONCAT44(param_2 >> (bVar3 & 0x1f), param_1 >> (bVar3 & 0x1f) | param_2 << (bVar2 & 0x1f));
        iVar5 = (int)(uVar1 % (ulonglong)uVar4);
        uVar1 = (uVar1 / uVar4 & 0xffffffff) * (ulonglong)param_3;
        if ((CONCAT44(iVar5,uVar6) < uVar1) || ((0 && (uVar6 < (uint)uVar1)))) {
            uVar1 = uVar1 - CONCAT44(uVar4,param_3);
        }
        uVar4 = (iVar5 - (int)(uVar1 >> 0x20)) - (uint)(uVar6 < (uint )uVar1);
        return CONCAT44(uVar4 >> (bVar2 & 0x1f),
                        uVar4 << (bVar3 & 0x1f) | uVar6 - (uint)uVar1 >>  (bVar2 & 0x1f));
        }
        if ((param_4 < param_2) || (param_3 <= param_1)) {
        bVar7 = param_1 < param_3;
        param_1 = param_1 - param_3;
        param_2 = (param_2 - param_4) - (uint)bVar7;
        }
        return CONCAT44(param_2,param_1);
    }
    return CONCAT44(param_2,param_1);
}

//                0x63763789,    0xd81,        0x10001,       0,          0x63763789,                0xd81
ulonglong generateKey(uint param_1,int param_2,uint param_3,uint param_4, uint param_5, uint param_6){
    ulonglong uVar1;
    ulonglong uVar2;
    uint uVar3;
    int iVar4;
    uint local_2c;
    uint local_28;
    uint local_24;
    int local_20;
    uint local_14;
    int local_10;
    
    local_24 = param_1; //0x63763789
    local_20 = param_2; //0xd81
    local_28 = param_4; //0
    local_14 = 1;
    local_10 = 0;
    for (local_2c = param_3; (local_2c | local_28) != 0; local_2c = local_2c >> 1 | uVar3) {
        if ((local_2c & 1) != 0) {
        iVar4 = local_20 * local_14;
        uVar1 = (ulonglong)local_14;
        local_14 = (uint)(local_24 * uVar1);
        local_10 = local_10 * local_24 + iVar4 + (int)(local_24 * uVar1 >> 0x20);
        }
        uVar3 = local_28 << 0x1f;
        local_28 = local_28 >> 1;
        iVar4 = local_20 * local_24;
        local_20 = local_20 * local_24;
        uVar1 = (ulonglong)local_24;
        uVar2 = (ulonglong)local_24;
        local_24 = (uint)(uVar1 * uVar2);
        local_20 = iVar4 + local_20 + (int)(uVar1 * uVar2 >> 0x20);
    }
    return __umoddi3(local_14,local_10,param_5,param_6);
}

void encrypt2(FILE *param_1, char* newfile){
    uint uVar1;
    byte bVar2;
    byte bVar3;
    uint uVar4;
    byte local_40 [16];
    byte local_30;
    byte local_29;
    int local_28;
    ulonglong key;
    uint local_18;
    byte local_11;
    int iter;
    
    key = generateKey(0x63763789,0xd81,0x10001,0,0x63763789,0xd81);
    uVar4 = (uint)(key >> 0x20);
    for (iter = 1; iter < 9; iter = iter + 1) {
        bVar3 = (byte)(iter * 8);
        bVar2 = bVar3 & 0x1f;
        bVar2 = (byte)((uint)key >> bVar2) | (byte)(uVar4 << 0x20 - bVar2);
        if ((iter * 8 & 0x20U) != 0) {
        bVar2 = (byte)(uVar4 >> (bVar3 & 0x1f));
        }
        local_40[iter] = bVar2;
        uVar1 = (7 - iter) * 8;
        bVar3 = (byte)uVar1;
        bVar2 = bVar3 & 0x1f;
        bVar2 = (byte)((uint)key >> bVar2) | (byte)(uVar4 << 0x20 - bVar2);
        if ((uVar1 & 0x20) != 0) {
        bVar2 = (byte)(uVar4 >> (bVar3 & 0x1f));
        }
        (&local_30)[-iter] = bVar2;
    }
    local_11 = 0;
    local_18 = 0;
    

    byte buf [100];
    uint filesize = 0;


    while( 1 ) {
        local_28 = fgetc(param_1);
        if (local_28 == -1) break;
        //fseek(param_1,-1,1);
        local_11 = local_11 ^ (byte)local_28;
        local_30 = 2;
        local_29 = local_11 >> 2 | local_11 << 6;
        local_18 = local_18 + 5 & 0xe;
        local_28 = (int)(char)(byte)local_28 - (int)(char)local_40[local_18 + 1];
        local_11 = local_29;
        buf[filesize++]=local_28;
    }


    FILE* output = fopen(newfile, "wb");

    int i = 0;
    while( i < filesize ) {
        local_28 = buf[i++];
        if (local_28 == -1) break;
        //fseek(output,-1,1);
        local_28 = (int)(char)((byte)local_28 ^ local_11);
        local_11 = local_11 + 4;
        fputc(local_28,output);
    }
    fputc((int)(char)local_11,output);
    fclose(output);
    return;
}

void decrypt2(FILE *file, FILE* output){
    uint uVar1;
    byte bVar2;
    byte bVar3;
    uint uVar4;
    byte local_40 [16] = {1, 211, 7, 21, 107, 10, 0, 0, 0, 187, 211, 7, 21, 107, 10, 0};
    byte local_30;
    byte local_29;
    int local_28;
    ulonglong key;
    uint local_18;
    byte local_11;
    int iter;
/*
    key = generateKey(0x63763789,0xd81,0x10001,0,0x63763789,0xd81);
    uVar4 = (uint)(key >> 0x20);
    for (iter = 1; iter < 9; iter = iter + 1) {
        bVar3 = (byte)(iter * 8);
        bVar2 = bVar3 & 0x1f;
        bVar2 = (byte)((uint)key >> bVar2) | (byte)(uVar4 << 0x20 - bVar2);
        if ((iter * 8 & 0x20U) != 0) {
        bVar2 = (byte)(uVar4 >> (bVar3 & 0x1f));
        }
        local_40[iter] = bVar2;
        uVar1 = (7 - iter) * 8;
        bVar3 = (byte)uVar1;
        bVar2 = bVar3 & 0x1f;
        bVar2 = (byte)((uint)key >> bVar2) | (byte)(uVar4 << 0x20 - bVar2);
        if ((uVar1 & 0x20) != 0) {
        bVar2 = (byte)(uVar4 >> (bVar3 & 0x1f));
        }
        (&local_30)[-iter] = bVar2;
    }*/

    fseek(file, -1, 2);
    int nb_bytes = ftell(file);
    local_11 = (byte)fgetc(file);
    local_11 -= nb_bytes * 4;
    fseek(file, 0, 0);
    byte buf [100];
    uint filesize = 0;

    while(1){
        int byte_from_file = fgetc(file);
        if(byte_from_file == -1)break;
        byte_from_file = (int)(char)((byte)byte_from_file ^ local_11);
        local_11 += 4;
        //fputc(byte_from_file, output);
        buf[filesize++] = byte_from_file;
    }

    local_18 = 0;

    int i = 0;
    while(i < filesize-1){
        int byte_from_file = buf[i++];
        //if (byte_from_file == -1) break;
        //fseek(output,-1,1);
        local_18 = local_18 + 5 & 0xe;
        byte_from_file = (int)(char)(byte)byte_from_file + (int)(char)local_40[local_18 + 1];
        fputc(byte_from_file,output);
    }
    return;
}


int main(void) {

    /** ------------------------ SECTION ENCRYPT0 ------------------------ **/

    FILE* fp = fopen("/home/nathan/Documents/git/slb/Lab01/reverse_c/encrypted/confidential.txt", "rb+");
    FILE* output = fopen("/home/nathan/Documents/git/slb/Lab01/reverse_c/decrypted/confidential.txt","wb");

    if (fp == NULL || output == NULL) {
        perror("Failed to open file");
        return -1;
    }

    decrypt0(fp,output);
    fclose(fp);
    fclose(output);

    /** ------------------------ SECTION ENCRYPT1 ------------------------ **/

    FILE* fp1 = fopen("/home/nathan/Documents/git/slb/Lab01/reverse_c/encrypted/salary.txt", "rb+");
    FILE* output1 = fopen("/home/nathan/Documents/git/slb/Lab01/reverse_c/decrypted/salary.txt","wb");
    if (fp1 == NULL  || output1 == NULL) {
        perror("Failed to open file");
        return -1;
    }

    decrypt1(fp1, output1);
    fclose(fp1);
    fclose(output1);

    /** ------------------------ SECTION ENCRYPT2 ------------------------ **/

    FILE* fp2 = fopen("/home/nathan/Documents/git/slb/Lab01/reverse_c/encrypted/passwords.txt","rb+");
    FILE* output2 = fopen("/home/nathan/Documents/git/slb/Lab01/reverse_c/decrypted/passwords.txt","wb");

    if(fp2 == NULL || output2 == NULL) {
        perror("Failed to open file");
        return -1;
    }

    decrypt2(fp2,output2);
    fclose(fp2);
    fclose(output2);

    return 0;
}