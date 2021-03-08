// gcc vuln.c -no-pie -std=c99 -m32 -fno-stack-protector -w -o -static vuln.o

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void ask_for_name()
{
    char name[16] = {0};
    puts("What's your name?");
    gets(name);
    printf("Hi %s!\n", name);
}

int main()
{
    ask_for_name();
    return 0;
}
