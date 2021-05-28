
#include <stdio.h>
#include <stdlib.h>




char important_data[0x10] = "\x30\0\0\0\0\0\0\0";
char admin[0x10] = "???\0";


char *users[15];
int userCount = 0;

void create_user() {
    char *name = malloc(0x20);
    users[userCount] = name;

    printf("%s", "Name: ");
    read(0, name, 0x20);

    printf("User Index: %d\nName: %s\nLocation: %p\n", userCount, users[userCount], users[userCount]);
    userCount++;
}

void delete_user() {
    printf("Index: ");

    char input[2];
    read(0, input, sizeof(input));
    int choice = atoi(input);


    char *name = users[choice];
    printf("User %d:\n\tName: %s\n", choice, name, name);

    // Check user actually exists before freeing
    if(choice < 0 || choice >= userCount) {
        puts("Invalid Index!");
        return;
    }
    else {
        free(name);
        puts("User freed!");
    }
}

void complete_level() {
    if(strcmp(admin, "admin\n")) {
        puts("Level Complete!");
        return;
    }
}

void main_loop() {
    boolean flag = true;
    while(flag) {
        printf(">> ");

        char input[2];
        read(0, input, sizeof(input));
        int choice = atoi(input);

        switch (choice)
        {
            case 1:
                create_user();
                break;
            case 2:
                delete_user();
                break;
            case 3:
                complete_level();
            case 4:
                flag = false;
            default:
                break;
        }
    }
}

int main() {
    main_loop();
    return 0;
}
