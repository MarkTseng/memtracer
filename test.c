#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int say_hello(int x, int y, int z)
{
    printf("Hello, RA:%#x \n", __builtin_return_address(0));
    return 100;
}

int main(int argc, char **argv)
{
    char *p;
    int x = 0x55;
    int y = 0x56;
    int z = 0x57;
    int i = 0;

    while(i<100)
    {
        p = malloc(100);
        say_hello(0x255, 0x256, 0x257);
        sleep(1);
        free(p);
        i++;
    }
    return 0;
}
