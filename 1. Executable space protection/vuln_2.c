// gcc vuln.c -std=c99 -m32 -fno-stack-protector -w -o vuln.o

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int x = 1;

void ask_for_name()
{

    char name[16];
    puts("What's your name?");
    gets(name);
    printf("Hi %s!\n", name);
}

int main()
{
    ask_for_name();
    return 0;
}
