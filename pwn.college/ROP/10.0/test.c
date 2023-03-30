int main() {
    void *p = mmap(0, 0x138, 3, 34, 0, 0);
    if ( mprotect(p, 0x138, 5) )
        __assert_fail("mprotect(data.win_addr, 0x138, PROT_READ|PROT_EXEC) == 0", "<stdin>", 0x9Fu, "challenge");
}