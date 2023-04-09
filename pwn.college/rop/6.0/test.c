int main() {
    int x = open("flag.txt", 0);
    sendfile(0, x, 0, 1024);
}