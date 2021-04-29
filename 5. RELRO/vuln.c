// gcc vuln.c -std=c99 -m32 -fno-stack-protector -z execstack -w -o vuln.o

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>


int main()
{
    char buf[100];
    printf("Hello \n");
    scanf("%s",buf);
        while(strcmp(buf,"exit")) {
            printf("\n");
            printf(buf);
            scanf("%s",buf);
        }

    return 0;

}
