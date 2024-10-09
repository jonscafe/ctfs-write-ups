#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <linux/mman.h>

const char vaints[] = "Vaints kozaki";

int is_vaints_approved(char c) {
    for (int i = 0; i < strlen(vaints); i++) {
        if (vaints[i] == c) return 1;
    }
    return 0;
}

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    char *rwx = mmap((void *)0x13370000, 0x105, 7, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    if (rwx == MAP_FAILED) {
        perror("mmap");
        return 0;
    }

    puts("# ================================= #");
    puts("# Vaints' Shellcode Executor🥶😱🔥  #");
    puts("# ================================= #");
    puts("Re Ai 105°C De Ni");
    puts("\tSuper idol de xiào róng\n\tDōu méi nǐ de tián\n\tBā yuè zhèng wǔ de yáng guāng\n\tDōu méi nǐ yào yǎn\n\tRè ài yì bǎi líng wǔ dù de nǐ\n\tDī dī qīng chún de zhēng liú shuǐ\n");
    printf("Kodenya gan: ");
    int n = read(0, rwx, 0x105);
    if (n < 1) {
        puts("negative infinity vaints point");
        return 0;
    }
    if (rwx[n-1] == '\n') rwx[n-1] = vaints[0];
    for (int i = 0; i < n; i++) {
        if (!is_vaints_approved(rwx[i])) {
            puts("negative infinity vaints point");
            return 0;
        }
    }
    ((void (*)())rwx)();
}