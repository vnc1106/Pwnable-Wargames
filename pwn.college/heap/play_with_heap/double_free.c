int main() {
    unsigned long *a;
    a = malloc(128);
    printf("[+] pointer 'a': %p\n", a);
    
    // corrupt tcache entry of 'a'
    a[1] = 1234;

    free(a);
    free(a);

    unsigned long *b = malloc(128);
    unsigned long *c = malloc(128);

    printf("[+] pointer 'b': %p\n", b);
    printf("[+] pointer 'c': %p\n", c);
}