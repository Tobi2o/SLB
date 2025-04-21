#include <stdio.h>
#include <string.h>
int main (int argc, char* argv[]){
        if (argc != 2)
        {
                printf("One argument required!\n");
                return 1;
        }
        int authenticated = 0;
        char password[8] ={0};
        strcpy(password, argv[1]);
        if(authenticated)
                printf("Congratulations!\n");
        else
                printf("You are not authenticated!\n");
        return 0;
}
