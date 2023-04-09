#include <stdio.h>

struct item_struct
{
    char *name;
    __uint64_t value;
    struct item_struct *fd;
    struct item_struct *bk;
};

int main () {
    struct item_struct tmp;
    asprintf(&tmp.name, "%s", "iPhone 8");
    tmp.value = 0x1337;
    printf("%s\n", tmp.name);
    
}