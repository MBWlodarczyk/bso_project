// gcc vuln.c -std=c99 -m32 -fno-stack-protector -w -o vuln.o

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void secret() {
    system("sh");
}

void ask_for_name()
{
    char name[100];
    puts("What's your name?");
    scanf("%s",name);
    printf("Hi %s!\n", name);
}

int main()
{
    ask_for_name();
    return 0;
}
